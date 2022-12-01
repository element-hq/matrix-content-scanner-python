#  Copyright 2022 New Vector Ltd
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
import asyncio
import hashlib
import logging
import os
import subprocess
from asyncio import Future
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

import attr
from cachetools import TTLCache
from canonicaljson import encode_canonical_json
from humanfriendly import format_size
from mautrix.crypto.attachments import decrypt_attachment
from mautrix.errors import DecryptionError
from mautrix.util import magic
from multidict import MultiDictProxy

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
    media_hash: Optional[str] = None

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
        self._result_cache: TTLCache[str, CacheEntry] = TTLCache(
            maxsize=mcs.config.result_cache.max_size,
            ttl=mcs.config.result_cache.ttl,
        )

        if mcs.config.result_cache.exit_codes_to_ignore is None:
            self._exit_codes_to_ignore = []
        else:
            self._exit_codes_to_ignore = mcs.config.result_cache.exit_codes_to_ignore

        self._max_size_to_cache = mcs.config.result_cache.max_file_size

        # List of MIME types we should allow. If None, we don't fail files based on their
        # MIME types (besides comparing it with the Content-Type header from the server
        # for unencrypted files).
        self._allowed_mimetypes = mcs.config.scan.allowed_mimetypes

        # Cache of futures for files that are currently scanning and downloading, so that
        # concurrent requests don't cause a file to be downloaded and scanned twice.
        self._current_scans: Dict[str, Future[MediaDescription]] = {}

    async def scan_file(
        self,
        media_path: str,
        metadata: Optional[JsonDict] = None,
        thumbnail_params: Optional[MultiDictProxy[str]] = None,
    ) -> MediaDescription:
        """Download and scan the given media.

        Unless the scan fails with one of the codes listed in `do_not_cache_exit_codes`,
        also cache the result.

        If the file already has an entry in the result cache, return this value without
        downloading the file again (unless we purposefully did not cache the file's
        content to save up on memory).

        If a file is currently already being downloaded or scanned as a result of another
        request, don't download it again and use the result from the first request.

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
        # Compute the key to use when caching, both in the current scans cache and in the
        # results cache.
        cache_key = self._get_cache_key_for_file(media_path, metadata, thumbnail_params)
        if cache_key not in self._current_scans:
            # Create a future in the context of the current event loop.
            loop = asyncio.get_event_loop()
            f = loop.create_future()
            # Register the future in the current scans cache so that subsequent queries
            # can use it.
            self._current_scans[cache_key] = f
            # Try to download and scan the file.
            try:
                res = await self._scan_file(
                    cache_key, media_path, metadata, thumbnail_params
                )
                # Set the future's result, and mark it as done.
                f.set_result(res)
                # Return the result.
                return res
            except Exception as e:
                # If there's an exception, catch it, pass it on to the future, and raise
                # it.
                f.set_exception(e)
                # We retrieve the exception from the future, because if we don't and no
                # other request is awaiting on the future, asyncio complains about "Future
                # exception was never retrieved".
                f.exception()
                raise
            finally:
                # Remove the future from the cache.
                del self._current_scans[cache_key]

        return await self._current_scans[cache_key]

    async def _scan_file(
        self,
        cache_key: str,
        media_path: str,
        metadata: Optional[JsonDict] = None,
        thumbnail_params: Optional[MultiDictProxy[str]] = None,
    ) -> MediaDescription:
        """Download and scan the given media.

        Unless the scan fails with one of the codes listed in `do_not_cache_exit_codes`,
        also cache the result.

        If the file already has an entry in the result cache, return this value without
        downloading the file again (unless we purposefully did not cache the file's
        content to save up on memory).

        Args:
            cache_key: The key to use to cache the result of the scan in the result cache.
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
        # The media to scan.
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
            media_hash = hashlib.sha256(media.content).hexdigest()
            if media_hash == cache_entry.media_hash:
                return media

            logger.warning(
                "Media has changed since last scan (cached hash: %s, new hash: %s),"
                " discarding cached result and scanning again",
                cache_entry.media_hash,
                media_hash,
            )

            del self._result_cache[cache_key]

        # Check if the media path is valid and only contains one slash (otherwise we'll
        # have issues parsing it further down the line).
        if media_path.count("/") != 1:
            info = "Malformed media ID"
            self._result_cache[cache_key] = CacheEntry(
                result=False,
                info=info,
            )
            raise FileDirtyError(info)

        # Download the file if we don't already have it.
        if media is None:
            media = await self._file_downloader.download_file(
                media_path=media_path,
                thumbnail_params=thumbnail_params,
            )

        # Download and scan the file.
        try:
            media, cacheable = await self._scan_media(media, media_path, metadata)
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
            # it's the right one. We get a hex digest in case we want to print it later.
            media_hash = hashlib.sha256(media.content).hexdigest()

            self._result_cache[cache_key] = CacheEntry(
                result=True,
                media=cached_media,
                media_hash=media_hash,
            )

        return media

    async def _scan_media(
        self,
        media: MediaDescription,
        media_path: str,
        metadata: Optional[JsonDict] = None,
    ) -> Tuple[MediaDescription, bool]:
        """Scans the given media.

        Args:
            media: The already downloaded media. If provided, the download step is
                skipped. Usually provided if we've re-downloaded a file with a cached
                result, but the file changed since the initial scan.
            media_path: The `server_name/media_id` path for the media.
            metadata: The metadata attached to the file (e.g. decryption key), or None if
                the file isn't encrypted.

        Returns:
            A description of the media, as well as a boolean indicating whether the
            successful scan result should be cached or not.

        Raises:
            FileDirtyError if the result of the scan said that the file is dirty, or if
                the media path is malformed.
        """

        # Decrypt the content if necessary.
        media_content = media.content
        if metadata is not None:
            # If the file is encrypted, we need to decrypt it before we can scan it.
            media_content = self._decrypt_file(media_content, metadata)

        # Check the file's MIME type to see if it's allowed and, if the file is not
        # encrypted, if it matches the Content-Type header the homeserver sent us.
        self._check_mimetype(
            media_content=media_content,
            claimed_mimetype=media.content_type,
            encrypted=metadata is not None,
        )

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
        thumbnail_params: Optional[MultiDictProxy[str]],
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
        # If we're provided with thumbnailing parameters, turn them into a structure that
        # can be serialised as JSON.
        thumbnail_params_json: Optional[Dict[str, List[str]]] = None
        if thumbnail_params is not None:
            thumbnail_params_json = {}
            for k in thumbnail_params.keys():
                thumbnail_params_json[k] = thumbnail_params.getall(k)

        hash = hashlib.sha256()
        hash.update(media_path.encode("utf8"))
        hash.update(b"\0")
        hash.update(encode_canonical_json(metadata))
        hash.update(b"\0")
        hash.update(encode_canonical_json(thumbnail_params_json))

        return hash.hexdigest()

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
        logger.info("Decrypting encrypted file")

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

    def _check_mimetype(
        self,
        media_content: bytes,
        claimed_mimetype: str,
        encrypted: bool,
    ) -> None:
        """Detects the MIME type of the provided bytes, and checks that:
        * it matches with the Content-Type header that was received when downloading this
            file (if the media isn't encrypted, since otherwise the Content-Type header
            is always 'application/octet-stream')
        * files with this MIME type are allowed (if an allow list is provided in the
            configuration)
        Args:
            media_content: The file's content. If the file is encrypted, this is its
                decrypted content.
            claimed_mimetype: The value of the Content-Type header received when
                downloading the file.
            encrypted: Whether the file was encrypted (in which case we don't want to
                check that its MIME type matches with the Content-Type header).
        Raises:
            FileDirtyError if one of the checks fail.
        """
        detected_mimetype = magic.mimetype(media_content)
        logger.debug("Detected MIME type for file is %s", detected_mimetype)

        # Check if the MIME type is matching the one that's expected, but only if the file
        # is not encrypted (because otherwise we'll always have 'application/octet-stream'
        # in the Content-Type header regardless of the actual MIME type of the file).
        if encrypted is False and detected_mimetype != claimed_mimetype:
            logger.error(
                "Mismatching MIME type (%s) and Content-Type header (%s)",
                detected_mimetype,
                claimed_mimetype,
            )
            raise FileDirtyError("File type not supported")

        # If there's an allow list for MIME types, check that the MIME type that's been
        # detected for this file is in it.
        if (
            self._allowed_mimetypes is not None
            and detected_mimetype not in self._allowed_mimetypes
        ):
            logger.error(
                "MIME type for file is forbidden: %s",
                detected_mimetype,
            )
            raise FileDirtyError("File type not supported")
