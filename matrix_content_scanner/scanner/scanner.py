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
import logging
import os.path
import subprocess
from typing import TYPE_CHECKING, Dict, List, Optional

import attr
from mautrix.crypto.attachments import decrypt_attachment
from mautrix.errors import DecryptionError

from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError, FileDirtyError
from matrix_content_scanner.utils.types import JsonDict, MediaDescription

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


@attr.s(auto_attribs=True, frozen=True)
class CacheEntry:
    result: bool
    media: Optional[MediaDescription] = None
    info: Optional[str] = None


class Scanner:
    def __init__(self, mcs: "MatrixContentScanner"):
        self._file_downloader = mcs.file_downloader
        self._script = mcs.config.scan.script
        self._removal_command = mcs.config.scan.removal_command
        self._store_directory = os.path.abspath(mcs.config.scan.temp_directory)

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
        downloading the file again.

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
        # Check if the media path is valid and only contains one slash (otherwise we'll
        # have issues parsing it further down the line).
        if media_path.count("/") != 1:
            raise FileDirtyError("Malformed media ID")

        # Download the file, and decrypt it if necessary.
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

        # Delete the file now that we've scanned it.
        logger.info("Scan has finished, removing file")
        removal_command_parts = self._removal_command.split()
        removal_command_parts.append(file_path)
        subprocess.run(removal_command_parts)

        # Raise an error if the result isn't clean.
        if result is False:
            raise FileDirtyError()

        return media

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
        # Figure out the full absolute path for this file. Given _store_directory is
        # already an absolute path using os.path.join is likely good enough, but we want
        # to make sure there isn't any '..' etc in the full path, to make sure we don't
        # try to write outside the directory.
        full_path = os.path.abspath(os.path.join(self._store_directory, media_path))
        if not full_path.startswith(self._store_directory):
            raise FileDirtyError("Malformed media ID")

        logger.info("Writing file to %s", full_path)

        # Create any directory we need.
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        with open(full_path, "wb") as fp:
            fp.write(body)

        return full_path

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
