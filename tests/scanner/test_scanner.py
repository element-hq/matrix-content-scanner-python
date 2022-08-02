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
import copy
from typing import Dict, List, Optional
from unittest.mock import Mock

import aiounittest
from twisted.web.http_headers import Headers

from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError, FileDirtyError
from matrix_content_scanner.utils.types import MediaDescription
from tests.testutils import (
    ENCRYPTED_FILE_METADATA,
    MEDIA_PATH,
    SMALL_PNG,
    SMALL_PNG_ENCRYPTED,
    get_content_scanner,
)


class ScannerTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        self.downloader_res = MediaDescription(
            content_type="image/png",
            content=SMALL_PNG,
            response_headers=Headers(),
        )

        async def download_file(
            media_path: str,
            thumbnail_params: Optional[Dict[str, List[str]]] = None,
        ) -> MediaDescription:
            """Mock for the file downloader's `download_file` method."""
            return self.downloader_res

        self.downloader_mock = Mock(side_effect=download_file)

        # Mock download_file so we don't actually try to download files.
        mcs = get_content_scanner()
        mcs.file_downloader.download_file = self.downloader_mock  # type: ignore[assignment]
        self.scanner = mcs.scanner

    async def test_scan(self) -> None:
        """Tests that we can scan files and that the scanner returns the media scanned if
        the scan was successful.
        """
        media = await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(media.content, SMALL_PNG)

    async def test_scan_dirty(self) -> None:
        """Tests that the scanner raises a FileDirtyError if the scan fails."""
        self.scanner._script = "false"
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file(MEDIA_PATH)

    async def test_encrypted_file(self) -> None:
        """Tests that the scanner can decrypt and scan encrypted files, and that if the
        scan is successful it returns the encrypted file and not the decrypted version.
        """
        self._setup_encrypted()

        media = await self.scanner.scan_file(MEDIA_PATH, ENCRYPTED_FILE_METADATA)
        self.assertEqual(media.content, SMALL_PNG_ENCRYPTED)

    async def test_different_encryption_key(self) -> None:
        """Tests that if some of the file's metadata changed, we don't match against the
        cache and we download the file again.

        Also tests that the scanner fails in the correct way if it can't decrypt a file.
        """
        self._setup_encrypted()

        # Scan the file and check that the downloader was called.
        await self.scanner.scan_file(MEDIA_PATH, ENCRYPTED_FILE_METADATA)
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Copy the file metadata and change the key.
        modified_metadata = copy.deepcopy(ENCRYPTED_FILE_METADATA)
        modified_metadata["file"]["key"]["k"] = "somethingelse"

        # This causes the scanner to not be able to decrypt the file.
        with self.assertRaises(ContentScannerRestError) as cm:
            await self.scanner.scan_file(MEDIA_PATH, modified_metadata)

        self.assertEqual(cm.exception.http_status, 400)
        self.assertEqual(cm.exception.reason, ErrCode.FAILED_TO_DECRYPT)

        # But it also causes it to be downloaded again because its metadata have changed.
        self.assertEqual(self.downloader_mock.call_count, 2)

    async def test_outside_temp_dir(self) -> None:
        """Tests that a scan is failed if the media path is formed in a way that would
        cause the scanner to write outside of the configured directory.
        """
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file("../bar")

    async def test_invalid_media_path(self) -> None:
        """Tests that a scan fails if the media path is invalid."""
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file(MEDIA_PATH + "/baz")

    def _setup_encrypted(self) -> None:
        """Sets up class properties to make the downloader return an encrypted file
        instead of a plain text one.
        """
        self.downloader_res.content_type = "application/octet-stream"
        self.downloader_res.content = SMALL_PNG_ENCRYPTED
