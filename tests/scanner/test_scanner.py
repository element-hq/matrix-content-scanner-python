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

from matrix_content_scanner.scanner.scanner import CacheEntry
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

    async def test_cache(self) -> None:
        """Tests that scan results are cached."""
        # Scan the file a first time, and check that the downloader has been called.
        await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Scan the file a second time, and check that the downloader has not been called
        # this time.
        media = await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(self.downloader_mock.call_count, 1)
        self.assertEqual(media.content, SMALL_PNG)

    async def test_cache_encrypted(self) -> None:
        """Tests that scan results for encrypted files are cached, and that the cached
        file is the encrypted version, not the decrypted one."""
        self._setup_encrypted()

        # Scan the file a first time, and check that the downloader has been called.
        await self.scanner.scan_file(MEDIA_PATH, ENCRYPTED_FILE_METADATA)
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Scan the file a second time, and check that the downloader has not been called
        # this time, and that the media returned is the encrypted copy.
        media = await self.scanner.scan_file(MEDIA_PATH, ENCRYPTED_FILE_METADATA)
        self.assertEqual(self.downloader_mock.call_count, 1)
        self.assertEqual(media.content, SMALL_PNG_ENCRYPTED)

    async def test_cache_download_thumbnail(self) -> None:
        """Tests that cached results for full file downloads are not used for thumbnails."""
        await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(self.downloader_mock.call_count, 1)

        await self.scanner.scan_file(MEDIA_PATH, thumbnail_params={"width": ["50"]})
        self.assertEqual(self.downloader_mock.call_count, 2)

    async def test_cache_thumbnail_params(self) -> None:
        """Tests that cached results for thumbnails are only used if the generation
        parameters are the same.
        """
        # Scan a thumbnail and check that the downloader was called.
        await self.scanner.scan_file(MEDIA_PATH, thumbnail_params={"width": ["50"]})
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Scan the thumbnail again and check that the cache result was used (since the
        # downloader was not called)
        await self.scanner.scan_file(MEDIA_PATH, thumbnail_params={"width": ["50"]})
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Scan a different thumbnail of the same media (with different parameters) and
        # check that the downloader was called.
        await self.scanner.scan_file(MEDIA_PATH, thumbnail_params={"height": ["50"]})
        self.assertEqual(self.downloader_mock.call_count, 2)

    async def test_cache_max_size(self) -> None:
        """Tests that we don't cache files if they exceed the configured maximum file
        size.
        """
        # Set the maximum file size to be just under the size of the file.
        self.scanner._max_size_to_cache = len(SMALL_PNG) - 1

        # Scan the file a first time, and check that the downloader has been called.
        await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Scan the file a second time, and check that the downloader has been called
        # again.
        media = await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(self.downloader_mock.call_count, 2)
        self.assertEqual(media.content, SMALL_PNG)

    async def test_cache_max_size_mismatching_hash(self) -> None:
        """Tests that we re-scan big files if the hash we have cached for them does not
        match the hash of the newly downloaded content.
        """
        # Mock the _run_scan command so we can keep track of its call count.
        mock_runner = Mock(return_value=0)
        self.scanner._run_scan = mock_runner  # type: ignore[assignment]

        # Calculate the cache key for this file so we can look it up later.
        cache_key = self.scanner._get_cache_key_for_file(MEDIA_PATH, None, None)

        # Set the maximum file size to be just under the size of the file.
        self.scanner._max_size_to_cache = len(SMALL_PNG) - 1

        # Make sure the cache is empty.
        self.assertEqual(len(self.scanner._result_cache), 0)

        # Scan the file a first time, and check that the file has been scanned.
        await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(self.downloader_mock.call_count, 1)
        mock_runner.assert_called_once()

        # Test that the file has been cached.
        self.assertIn(cache_key, self.scanner._result_cache)

        # Change the hash of the cache entry to force it to be scanned again.
        entry: CacheEntry = self.scanner._result_cache[cache_key]
        self.scanner._result_cache[cache_key] = CacheEntry(
            result=entry.result,
            media=entry.media,
            media_hash="BAD_HASH",
            info=entry.info,
        )

        # Run the scanner again and check that the cache entry for the file has been
        # discarded (i.e. the scan is run again).
        await self.scanner.scan_file(MEDIA_PATH)
        self.assertEqual(mock_runner.call_count, 2)

        # Also check that the file has only been re-downloaded once.
        self.assertEqual(self.downloader_mock.call_count, 2)

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

    async def test_dont_cache_exit_codes(self) -> None:
        """Tests that if the configuration specifies exit codes to ignore when running
        the scanning script, we don't cache them.
        """
        self.scanner._exit_codes_to_ignore = [5]

        # It's tricky to give a value to `scanner._script` that makes `_run_scan` return 5
        # directly, so we just mock it here.
        run_scan_mock = Mock(return_value=5)
        self.scanner._run_scan = run_scan_mock  # type: ignore[assignment]

        # Scan the file, we'll check later that it wasn't cached.
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file(MEDIA_PATH)

        self.assertEqual(self.downloader_mock.call_count, 1)

        # Update the mock so that the file is cached at the next scan.
        run_scan_mock.return_value = 1

        # Scan the file again to check that the file wasn't cached.
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file(MEDIA_PATH)

        self.assertEqual(self.downloader_mock.call_count, 2)

        # The file should be cached now.
        with self.assertRaises(FileDirtyError):
            await self.scanner.scan_file(MEDIA_PATH)

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
