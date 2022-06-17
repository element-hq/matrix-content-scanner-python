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
import json
from typing import Tuple, Union
from unittest.mock import Mock, call

import aiounittest
from twisted.web.http_headers import Headers

from matrix_content_scanner.utils.errors import (
    ContentScannerRestError,
    WellKnownDiscoveryError,
)
from matrix_content_scanner.utils.types import JsonDict
from tests.testutils import (
    MEDIA_PATH,
    SMALL_PNG,
    get_base_media_headers,
    get_content_scanner,
)


class FileDownloaderTestCase(aiounittest.AsyncTestCase):
    def setUp(self) -> None:
        # Set a fixed base URL so that .well-known discovery doesn't get in the way.
        content_scanner = get_content_scanner(
            {"download": {"base_homeserver_url": "http://my-site.com"}}
        )
        self.downloader = content_scanner.file_downloader

        self.media_status = 200
        self.media_body = SMALL_PNG
        self.media_headers = get_base_media_headers()

        async def _get(url: str) -> Tuple[int, bytes, Headers]:
            """Mock for the _get method on the file downloader that doesn't serve a
            .well-known client file.
            """
            if (
                url.endswith("/_matrix/media/v3/download/" + MEDIA_PATH)
                or "/_matrix/media/v3/thumbnail/" + MEDIA_PATH in url
                or url.endswith("/_matrix/media/r0/download/" + MEDIA_PATH)
                or "/_matrix/media/r0/thumbnail/" + MEDIA_PATH in url
            ):
                return self.media_status, self.media_body, self.media_headers
            elif url.endswith("/.well-known/matrix/client"):
                return 404, b"Not found", Headers()

            raise RuntimeError("Unexpected request on %s" % url)

        # Mock _get so we don't actually try to download files.
        self.get_mock = Mock(side_effect=_get)
        self.downloader._get = self.get_mock  # type: ignore[assignment]

    async def test_download(self) -> None:
        """Tests that downloading a file works."""
        media = await self.downloader.download_file(MEDIA_PATH)
        self.assertEqual(media.content, SMALL_PNG)
        self.assertEqual(media.content_type, "image/png")

        # Check that we tried downloading from the set base URL.
        args = self.get_mock.call_args
        self.assertTrue(args[0][0].startswith("http://my-site.com/"))

    async def test_no_base_url(self) -> None:
        """Tests that configuring a base homeserver URL means files are downloaded from
        that homeserver (rather than the one the files were uploaded to) and .well-known
        discovery is bypassed.
        """
        self.downloader._base_url = None
        await self.downloader.download_file(MEDIA_PATH)

        # # Check that we've tried making a .well-known discovery request before
        # # downloading the file.
        # self.assertEqual(self.get_mock.call_count, 1)
        # self.assertEqual(
        #     self.get_mock.mock_calls[0], call("https://foo/.well-known/matrix/client")
        # )
        # self.assertEqual(
        #     self.get_mock.mock_calls[1],
        #     call("https://foo/_matrix/media/v3/download/" + MEDIA_PATH),
        # )

        self.assertEqual(
            self.get_mock.mock_calls[0],
            call("https://foo/_matrix/media/v3/download/" + MEDIA_PATH),
        )

    async def test_retry_on_404(self) -> None:
        """Tests that if we get a 404 when trying to download a file on a v3 path, we
        retry with an r0 path for backwards compatibility.
        """
        self.media_status = 404
        self.media_body = b"Not found"
        self.media_headers.setRawHeaders("content-type", ["text/plain"])

        await self._test_retry()

    async def test_retry_on_unrecognised(self) -> None:
        """Tests that if we get a Synapse-style M_UNRECOGNIZED response when trying to
        download a file on a v3 path, we retry with an r0 path for backwards
        compatibility.
        """
        self.media_status = 400
        self.media_body = b'{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}'
        self.media_headers.setRawHeaders("content-type", ["application/json"])

        await self._test_retry()

    async def _test_retry(self) -> None:
        """Tests that in a set specific case a failure to download a file from a v3
        download path means we retry the request on an r0 one for backwards compatibility.
        """
        # Check that we eventually fail at downloading the file.
        with self.assertRaises(ContentScannerRestError) as cm:
            await self.downloader.download_file(MEDIA_PATH)

        self.assertEqual(cm.exception.http_status, 502)
        self.assertEqual(cm.exception.info, "File not found")

        # Check that we sent out two requests: one to the v3 path and one to the r0 path.
        self.assertEqual(self.get_mock.call_count, 2)
        self.assertEqual(
            self.get_mock.mock_calls[0],
            call("http://my-site.com/_matrix/media/v3/download/" + MEDIA_PATH),
        )
        self.assertEqual(
            self.get_mock.mock_calls[1],
            call("http://my-site.com/_matrix/media/r0/download/" + MEDIA_PATH),
        )

    async def test_thumbnail(self) -> None:
        """Tests that we can download a thumbnail and that the parameters to generate the
        thumbnail are correctly passed on to the homeserver.
        """
        await self.downloader.download_file(MEDIA_PATH, {"height": ["50"]})
        self.assertTrue(
            self.get_mock.call_args[0][0].endswith(
                "/thumbnail/%s?height=50" % MEDIA_PATH
            )
        )

    async def test_multiple_content_type(self) -> None:
        """Tests that we raise an error if the homeserver responds with too many
        Content-Type headers.
        """
        self.media_headers.setRawHeaders("content-type", ["image/jpeg", "image/png"])

        with self.assertRaises(ContentScannerRestError) as cm:
            await self.downloader.download_file(MEDIA_PATH)

        self.assertEqual(cm.exception.http_status, 502)
        self.assertTrue("Content-Type" in cm.exception.info)

    async def test_no_content_type(self) -> None:
        """Tests that we raise an error if the homeserver responds with no Content-Type
        headers.
        """
        self.media_headers.removeHeader("content-type")

        with self.assertRaises(ContentScannerRestError) as cm:
            await self.downloader.download_file(MEDIA_PATH)

        self.assertEqual(cm.exception.http_status, 502)
        self.assertTrue("Content-Type" in cm.exception.info)
