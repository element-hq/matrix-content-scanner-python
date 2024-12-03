#  Copyright 2023 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from http import HTTPStatus
from unittest.mock import patch

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
        # Bypass well-known lookups.
        self.scanner = get_content_scanner(
            {"download": {"base_homeserver_url": "http://my-site.com"}}
        )

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
