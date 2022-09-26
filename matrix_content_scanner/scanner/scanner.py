#  Copyright 2022 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import hashlib
import logging
import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import attr
from cachetools import TTLCache
from canonicaljson import encode_canonical_json
from humanfriendly import format_size
from mautrix.crypto.attachments import decrypt_attachment
from mautrix.errors import DecryptionError

from matrix_content_scanner.config import parse_duration, parse_size
from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError, FileDirtyError
from matrix_content_scanner.utils.types import JsonDict, MediaDescription

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


@attr.s(auto_attribs=True, frozen=True)
class CacheEntry:
    """An entry in the scanner's result cache."""

    # The result of the scan: True if the scan passed, False otherwise.
    result: bool
    # The media that was scanned, so we can return it in future requests. We only cache
    # it if the scan succeeded and the file's size does not exceed the configured limit,
    # otherwise it's None.
    media: Optional[MediaDescription] = None
    # Hash of the media content, so we can make sure no malicious servers changed the file
    # since we've scanned it (e.g. if we need to re-download it because the file was too
    # big). None if the scan failed.
    media_hash: Optional[bytes] = None
    # Info to include in the FileDirtyError if the scan failed.
    info: Optional[str] = None


class Scanner:
    def __init__(self, mcs: "MatrixContentScanner"):
        self._file_downloader = mcs.file_downloader
        self._script = mcs.config.scan.script
        self._removal_command = mcs.config.scan.removal_command
        self._store_directory = Path(mcs.config.scan.temp_directory).resolve(
            strict=True
        )

        # Result cache settings.
        cache_ttl = parse_duration(mcs.config.result_cache.ttl)
        # We know cache_ttl can't be None because the relevant configuration setting can't
        # be None.
        assert cache_ttl is not None

        self._result_cache: TTLCache[str, CacheEntry] = TTLCache(
            maxsize=mcs.config.result_cache.max_size,
            ttl=cache_ttl,
        )

        if mcs.config.result_cache.exit_codes_to_ignore is None:
            self._exit_codes_to_ignore = []
        else:
            self._exit_codes_to_ignore = mcs.config.result_cache.exit_codes_to_ignore

        self._max_size_to_cache = parse_size(mcs.config.result_cache.max_file_size)

    async def scan_file(
        self,
        media_path: str,
        metadata: Optional[JsonDict] = None,
        thumbnail_params: Optional[Dict[str, List[str]]] = None,
    ) -> MediaDescription:
        """Download and scan the given media.

        Unless the scan fails with one of the codes listed in `do_not_cache_exit_codes`,
        also cache the result.

        If the file already has an entry in the result cache, return this value without
        downloading the file again (unless we purposefully did not cache the file's
        content to save up on memory).

        Args:
            media_path: The `server_name/media_id` path for the media.
            metadata: The metadata attached to the file (e.g. decryption key), or None if
                the file isn't encrypted.
            thumbnail_params: If present, then we want to request and scan a thumbnail
                generated with the provided parameters instead of the full media.

        Returns:
            A description of the media.

        Raises:
            ContentScannerRestError if the file could not be downloaded.
            FileDirtyError if the result of the scan said that the file is dirty, or if
                the media path is malformed.
        """
        # Compute the cache key for the media.
        cache_key = self._get_cache_key_for_file(media_path, metadata, thumbnail_params)

        # The content of the file, if we have already scanned it. We might re-download
        # a file that was too large to cache, and then realise we need to scan it again
        # (because e.g. its hash has changed), in which case we set this to the file's
        # MediaDescription and give it to _download_and_scan to avoid it being scanned
        # again.
        media: Optional[MediaDescription] = None

        # Return the cached result if there's one.
        cache_entry = self._result_cache.get(cache_key)
        if cache_entry is not None:
            logger.info("Found a cached result %s", cache_entry.result)

            if cache_entry.result is False:
                # Feed the additional info we might have added when caching the error,
                # into the new error.
                raise FileDirtyError(info=cache_entry.info)

            if cache_entry.media is not None:
                return cache_entry.media

            # If we don't have the media cached
            logger.info(
                "Got a positive result from cache without a media, downloading file",
            )

            media = await self._file_downloader.download_file(
                media_path=media_path,
                thumbnail_params=thumbnail_params,
            )

            # Compare the media's hash to ensure the server hasn't changed the file since
            # the last scan. If it has changed, shout about it in the logs, discard the
            # cache entry and scan it again.
            media_hash = hashlib.sha256(media.content).digest()
            if media_hash == cache_entry.media_hash:
                return media

            logger.warning(
                "Media has changed since last scan, discarding cached result and"
                " scanning again"
            )

            del self._result_cache[cache_key]

        # Download and scan the file.
        try:
            media, cacheable = await self._download_and_scan(
                media_path, metadata, thumbnail_params, media
            )
        except FileDirtyError as e:
            if e.cacheable:
                logger.info("Caching scan failure")

                # If the test fails, don't store the media to save memory.
                self._result_cache[cache_key] = CacheEntry(
                    result=False,
                    media=None,
                    info=e.info,
                )

            raise

        # Update the cache if the result should be cached.
        if cacheable:
            logger.info("Caching scan success")

            cached_media: Optional[MediaDescription] = media

            if (
                self._max_size_to_cache is not None
                and len(media.content) > self._max_size_to_cache
            ):

                # Don't cache the file's content if it exceeds the maximum allowed file
                # size, to minimise memory usage.
                logger.info(
                    "File content has size %s, which is more than %s, not caching content",
                    format_size(len(media.content)),
                    format_size(self._max_size_to_cache),
                )

                cached_media = None

            # Hash the media, that way if we need to re-download the file we can make sure
            # it's the right one.
            media_hash = hashlib.sha256(media.content).digest()

            self._result_cache[cache_key] = CacheEntry(
                result=True,
                media=cached_media,
                media_hash=media_hash,
            )

        return media

    async def _download_and_scan(
        self,
        media_path: str,
        metadata: Optional[JsonDict] = None,
        thumbnail_params: Optional[Dict[str, List[str]]] = None,
        media: Optional[MediaDescription] = None,
    ) -> Tuple[MediaDescription, bool]:
        """Downloads and scans the given file.

        Args:
            media_path: The `server_name/media_id` path for the media.
            metadata: The metadata attached to the file (e.g. decryption key), or None if
                the file isn't encrypted.
            thumbnail_params: If present, then we want to request and scan a thumbnail
                generated with the provided parameters instead of the full media.
            media: The already downloaded media. If provided, the download step is
                skipped. Usually provided if we've re-downloaded a file with a cached
                result, but the file changed since the initial scan.

        Returns:
            A description of the media.

        Raises:
            ContentScannerRestError if the file could not be downloaded.
            FileDirtyError if the result of the scan said that the file is dirty, or if
                the media path is malformed.
        """
        # Check if the media path is valid and only contains one slash (otherwise we'll
        # have issues parsing it further down the line).
        if media_path.count("/") != 1:
            raise FileDirtyError("Malformed media ID")

        # Download the file and decrypt it if necessary.
        if media is None:
            media = await self._file_downloader.download_file(
                media_path=media_path,
                thumbnail_params=thumbnail_params,
            )

        media_content = media.content
        if metadata is not None:
            # If the file is encrypted, we need to decrypt it before we can scan it.
            media_content = self._decrypt_file(media_content, metadata)

        # Write the file to disk.
        file_path = self._write_file_to_disk(media_path, media_content)

        # Scan the file and see if the result is positive or negative.
        exit_code = self._run_scan(file_path)
        result = exit_code == 0

        # If the exit code isn't part of the ones we should ignore, cache the result.
        cacheable = True
        if exit_code in self._exit_codes_to_ignore:
            logger.info(
                "Scan returned exit code %d which must not be cached", exit_code
            )
            cacheable = False

        # Delete the file now that we've scanned it.
        logger.info("Scan has finished, removing file")
        removal_command_parts = self._removal_command.split()
        removal_command_parts.append(file_path)
        subprocess.run(removal_command_parts)

        # Raise an error if the result isn't clean.
        if result is False:
            raise FileDirtyError(cacheable=cacheable)

        return media, cacheable

    def _get_cache_key_for_file(
        self,
        media_path: str,
        metadata: Optional[JsonDict],
        thumbnail_params: Optional[Dict[str, List[str]]],
    ) -> str:
        """Generates the key to use to store the result for the given media in the result
        cache.

        The key is computed using the media's `server_name/media_id` path, but also the
        metadata dict (stringified), in case e.g. the decryption key changes, as well as
        the parameters used to generate the thumbnail if any (stringified), to
        differentiate thumbnails from full-sized media.
        The resulting key is a sha256 hash of the concatenation of these two values.

        Args:
            media_path: The `server_name/media_id` path of the file to scan.
            metadata: The file's metadata (or None if the file isn't encrypted).
            thumbnail_params: The parameters to generate thumbnail with. If no parameter
                is passed, this will be an empty dict. If the media being requested is not
                a thumbnail, this will be None.
        """
        raw_metadata = encode_canonical_json(metadata)
        raw_params = encode_canonical_json(thumbnail_params)
        media_path_bytes = media_path.encode("utf8")
        base_bytes = media_path_bytes + b"\0" + raw_metadata + b"\0" + raw_params

        return hashlib.sha256(base_bytes).hexdigest()

    def _decrypt_file(self, body: bytes, metadata: JsonDict) -> bytes:
        """Extract decryption information from the file's metadata and decrypt it.

        Args:
            body: The encrypted body of the file.
            metadata: The part of the request that includes decryption information.

        Returns:
            The decrypted content of the file.

        Raises:
            ContentScannerRestError(400) if the decryption failed.
        """
        logger.info("File is encrypted, decrypting")

        # At this point the schema should have been validated so we can pull these values
        # out safely.
        key = metadata["file"]["key"]["k"]
        hash = metadata["file"]["hashes"]["sha256"]
        iv = metadata["file"]["iv"]

        # Decrypt the file.
        try:
            return decrypt_attachment(body, key, hash, iv)
        except DecryptionError as e:
            raise ContentScannerRestError(
                http_status=400,
                reason=ErrCode.FAILED_TO_DECRYPT,
                info=e.message,
            )

    def _write_file_to_disk(self, media_path: str, body: bytes) -> str:
        """Writes the given content to disk. The final file name will be a concatenation
        of `temp_directory` and the media's `server_name/media_id` path.

        Args:
            media_path: The `server_name/media_id` path of the media we're processing.
            body: The bytes to write to disk.

        Returns:
            The full path to the newly written file.

        Raises:
            FileDirtyError if the media path is malformed in a way that would cause the
                file to be written outside the configured directory.
        """
        # Figure out the full absolute path for this file.
        full_path = self._store_directory.joinpath(media_path).resolve()
        try:
            # Check if the full path is a sub-path to the store's path, to make sure
            # there isn't any '..' etc. in the full path, which would cause us to try
            # writing outside the store's directory.
            full_path.relative_to(self._store_directory)
        except ValueError:
            raise FileDirtyError("Malformed media ID")

        logger.info("Writing file to %s", full_path)

        # Create any directory we need.
        os.makedirs(full_path.parent, exist_ok=True)

        with open(full_path, "wb") as fp:
            fp.write(body)

        return str(full_path)

    def _run_scan(self, file_name: str) -> int:
        """Runs the scan script, passing it the given file name.

        Args:
            file_name: Name of the file to scan.

        Returns:
            The exit code the script returned.
        """
        try:
            subprocess.run([self._script, file_name], check=True)
            logger.info("Scan succeeded")
            return 0
        except subprocess.CalledProcessError as e:
            logger.info("Scan failed with exit code %d: %s", e.returncode, e.stderr)
            return e.returncode
