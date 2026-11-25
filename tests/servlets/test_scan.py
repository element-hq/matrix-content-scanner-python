#  Copyright 2023 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from http import HTTPStatus
from unittest.mock import Mock, patch

from aiohttp.test_utils import AioHTTPTestCase
from aiohttp.web_app import Application
from multidict import CIMultiDict

from matrix_content_scanner.httpserver import HTTPServer
from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError

from tests.testutils import get_content_scanner

SERVER_NAME = "test"


class TestScanHandler(AioHTTPTestCase):
    def setUp(self) -> None:
        self.scanner = get_content_scanner()

    async def get_application(self) -> Application:
        return HTTPServer(self.scanner)._app

    async def test_media_not_found_on_remote_homeserver(self) -> None:
        """Missing media on the remote HS should be presented as a 404 to the client."""
        patch_downloader = patch.object(
            self.scanner.file_downloader,
            "_get",
            return_value=(HTTPStatus.NOT_FOUND, b"", CIMultiDict()),
        )

        with patch_downloader:
            async with self.client.get(
                f"/_matrix/media_proxy/unstable/download/{SERVER_NAME}/media-does-not-exist"
            ) as resp:
                self.assertEqual(resp.status, 404)
                body = await resp.json()
                self.assertEqual(body["reason"], "M_NOT_FOUND", body)

    async def test_remote_homeserver_unreachable(self) -> None:
        """An unreachable HS should be presented as a 502 to the client."""
        patch_downloader = patch.object(
            self.scanner.file_downloader,
            "_get",
            side_effect=ContentScannerRestError(
                HTTPStatus.BAD_GATEWAY,
                ErrCode.REQUEST_FAILED,
                "dodgy network timeout :(((",
            ),
        )

        with patch_downloader:
            async with self.client.get(
                f"/_matrix/media_proxy/unstable/download/{SERVER_NAME}/media-does-not-exist"
            ) as resp:
                self.assertEqual(resp.status, 502)
                body = await resp.json()
                self.assertEqual(body["reason"], "MCS_MEDIA_REQUEST_FAILED", body)

    async def test_malformed_media_path(self) -> None:
        """A media path that doesn't form a valid MXC URI should be rejected without
        trying to download the media.
        """
        download_mock = Mock()
        patch_downloader = patch.object(
            self.scanner.file_downloader, "download_file", download_mock
        )

        with patch_downloader:
            for media_path in ["foo", "foo/", "foo/bar/baz"]:
                with self.subTest(media_path=media_path):
                    for route in ["download", "thumbnail"]:
                        async with self.client.get(
                            f"/_matrix/media_proxy/unstable/{route}/{media_path}"
                        ) as resp:
                            self.assertEqual(resp.status, 403)
                            body = await resp.json()
                            self.assertEqual(body["reason"], "MCS_MEDIA_NOT_CLEAN")
                            self.assertEqual(body["info"], "Malformed media ID")

                    async with self.client.get(
                        f"/_matrix/media_proxy/unstable/scan/{media_path}"
                    ) as resp:
                        self.assertEqual(resp.status, 200)
                        body = await resp.json()
                        self.assertEqual(
                            body, {"clean": False, "info": "Malformed media ID"}
                        )

        download_mock.assert_not_called()
