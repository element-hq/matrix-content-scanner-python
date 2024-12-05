#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
import asyncio
import copy
from typing import Any, Dict, List, Optional
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock

from multidict import CIMultiDict, CIMultiDictProxy

from matrix_content_scanner.scanner.scanner import CacheEntry
from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import (
    ContentScannerRestError,
    FileDirtyError,
    FileMimeTypeForbiddenError,
)
from matrix_content_scanner.utils.types import MediaDescription

from tests.testutils import (
    ENCRYPTED_FILE_METADATA,
    MEDIA_PATH,
    SMALL_BINARY_FILE,
    SMALL_PNG,
    SMALL_PNG_ENCRYPTED,
    SMALL_TEXT_FILE,
    get_content_scanner,
    to_thumbnail_params,
)


class ScannerTestCase(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.downloader_res = MediaDescription(
            content_type="image/png",
            content=SMALL_PNG,
            response_headers=CIMultiDictProxy(CIMultiDict()),
        )

        async def download_file(
            media_path: str,
            thumbnail_params: Optional[Dict[str, List[str]]] = None,
            auth_header: Optional[str] = None,
        ) -> MediaDescription:
            """Mock for the file downloader's `download_file` method."""
            return self.downloader_res

        self.downloader_mock = Mock(side_effect=download_file)

        # Mock download_file so we don't actually try to download files.
        mcs = get_content_scanner()
        mcs.file_downloader.download_file = self.downloader_mock  # type: ignore[method-assign]
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

        await self.scanner.scan_file(
            MEDIA_PATH, thumbnail_params=to_thumbnail_params({"width": "50"})
        )
        self.assertEqual(self.downloader_mock.call_count, 2)

    async def test_cache_thumbnail_params(self) -> None:
        """Tests that cached results for thumbnails are only used if the generation
        parameters are the same.
        """
        # Scan a thumbnail and check that the downloader was called.
        await self.scanner.scan_file(
            MEDIA_PATH, thumbnail_params=to_thumbnail_params({"width": "50"})
        )
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Scan the thumbnail again and check that the cache result was used (since the
        # downloader was not called)
        await self.scanner.scan_file(
            MEDIA_PATH, thumbnail_params=to_thumbnail_params({"width": "50"})
        )
        self.assertEqual(self.downloader_mock.call_count, 1)

        # Scan a different thumbnail of the same media (with different parameters) and
        # check that the downloader was called.
        await self.scanner.scan_file(
            MEDIA_PATH, thumbnail_params=to_thumbnail_params({"height": "50"})
        )
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
        mock_runner = AsyncMock(return_value=0)
        self.scanner._run_scan = mock_runner  # type: ignore[method-assign]

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

    async def test_allowlist_mimetype(self) -> None:
        """Tests that, if there's an allow list for MIME types and the file's MIME type
        isn't in it, the file's scan fails.
        """
        # Set an allow list that only allows JPEG files.
        self.scanner._allowed_mimetypes = ["image/jpeg"]

        # Check that the scan fails since the file is a PNG.
        with self.assertRaises(FileMimeTypeForbiddenError):
            await self.scanner.scan_file(MEDIA_PATH)

    async def test_allowlist_mimetype_encrypted(self) -> None:
        """Tests that the file's MIME type is correctly detected and compared with the
        allow list (if set), even if it's encrypted.
        """
        self._setup_encrypted()

        # Set an allow list that only allows JPEG files.
        self.scanner._allowed_mimetypes = ["image/jpeg"]

        # Check that the scan fails since the file is a PNG.
        with self.assertRaises(FileMimeTypeForbiddenError):
            await self.scanner.scan_file(MEDIA_PATH, ENCRYPTED_FILE_METADATA)

    async def test_blocklist_mimetype(self) -> None:
        """Tests that, if there's an allow list for MIME types and the file's MIME type
        isn't in it, the file's scan fails.
        """
        # Set a block list that blocks PNG images.
        self.scanner._blocked_mimetypes = ["image/png"]

        # Check that the scan fails since the file is a PNG.
        with self.assertRaises(FileMimeTypeForbiddenError):
            await self.scanner.scan_file(MEDIA_PATH)

    async def test_blocklist_mimetype_encrypted(self) -> None:
        """Tests that the file's MIME type is correctly detected and compared with the
        allow list (if set), even if it's encrypted.
        """
        self._setup_encrypted()

        # Set a block list that blocks PNG images.
        self.scanner._blocked_mimetypes = ["image/png"]

        # Check that the scan fails since the file is a PNG.
        with self.assertRaises(FileMimeTypeForbiddenError):
            await self.scanner.scan_file(MEDIA_PATH, ENCRYPTED_FILE_METADATA)

    async def test_blocklist_mimetype_fallback_binary_file(self) -> None:
        """Tests that unrecognised binary files' MIME type is assumed to be
        `application/octet-stream` and that they can be blocked in this way.
        """

        self.downloader_res = MediaDescription(
            # This is the *claimed* content-type by the uploader
            content_type="application/vnd.io.element.generic_binary_file",
            content=SMALL_BINARY_FILE,
            response_headers=CIMultiDictProxy(CIMultiDict()),
        )

        # Set a block list that blocks uncategorised binary files.
        self.scanner._blocked_mimetypes = ["application/octet-stream"]

        with self.assertRaises(FileMimeTypeForbiddenError):
            await self.scanner.scan_file(MEDIA_PATH)

    async def test_blocklist_mimetype_fallback_text_file(self) -> None:
        """Tests that unrecognised text files' MIME type is assumed to be
        `text/plain` and that they can be blocked in this way.
        """

        self.downloader_res = MediaDescription(
            # This is the *claimed* content-type by the uploader
            content_type="application/vnd.io.element.generic_file",
            content=SMALL_TEXT_FILE,
            response_headers=CIMultiDictProxy(CIMultiDict()),
        )

        # Set a block list that blocks uncategorised text files.
        self.scanner._blocked_mimetypes = ["text/plain"]

        with self.assertRaises(FileMimeTypeForbiddenError):
            await self.scanner.scan_file(MEDIA_PATH)

    async def test_dont_cache_exit_codes(self) -> None:
        """Tests that if the configuration specifies exit codes to ignore when running
        the scanning script, we don't cache them.
        """
        self.scanner._exit_codes_to_ignore = [5]

        # It's tricky to give a value to `scanner._script` that makes `_run_scan` return 5
        # directly, so we just mock it here.
        run_scan_mock = AsyncMock(return_value=5)
        self.scanner._run_scan = run_scan_mock  # type: ignore[method-assign]

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

    async def test_deduplicate_scans(self) -> None:
        """Tests that if two scan requests come in for the same file and with the same
        parameter, only one download/scan happens.
        """

        # Change the Mock's side effect to introduce some delay, to simulate a long
        # download time. We sleep asynchronously to allow additional scans requests to be
        # processed.
        async def _scan_file(*args: Any) -> MediaDescription:
            await asyncio.sleep(0.2)

            return self.downloader_res

        scan_mock = Mock(side_effect=_scan_file)
        self.scanner._scan_file = scan_mock  # type: ignore[method-assign]

        # Request two scans of the same file at the same time.
        results = await asyncio.gather(
            asyncio.create_task(self.scanner.scan_file(MEDIA_PATH)),
            asyncio.create_task(self.scanner.scan_file(MEDIA_PATH)),
        )

        # Check that the scanner has only been called once, meaning that the second
        # call did not trigger a scan.
        scan_mock.assert_called_once()

        # Check that we got two results, and that we actually got the correct media
        # description in the second scan.
        self.assertEqual(len(results), 2, results)
        self.assertEqual(results[0].content, results[1].content, results)

    def _setup_encrypted(self) -> None:
        """Sets up class properties to make the downloader return an encrypted file
        instead of a plain text one.
        """
        self.downloader_res.content_type = "application/octet-stream"
        self.downloader_res.content = SMALL_PNG_ENCRYPTED
