#  Copyright 2025 DINUM
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import AioHTTPTestCase
from aiohttp.web_app import Application
from multidict import MultiDict

from matrix_content_scanner.httpserver import HTTPServer

from tests.testutils import get_content_scanner

BASE_URL = "http://test.org"
CONTENT_SCANNER_PATH = "/_matrix/media_proxy/unstable/download/test.org/mediaid"
MEDIA_PATH = "/_matrix/media/v3/download/test.org/mediaid"


class TestHeadersHandler(AioHTTPTestCase):
    def setUp(self) -> None:
        self.scanner = get_content_scanner(
            {
                "download": {
                    "base_homeserver_url": BASE_URL,
                    "additional_headers": {"Key": "Value"},
                    "headers_to_forward": ["Host"],
                }
            }
        )

    async def get_application(self) -> Application:
        return HTTPServer(self.scanner)._app

    def _set_get_response(
        self, mock_get: MagicMock, status: int, headers: dict[str, str]
    ) -> None:
        multidict_headers = MultiDict[str]()
        multidict_headers.extend(headers)
        mock_get.return_value.__aenter__.return_value.status = status
        mock_get.return_value.__aenter__.return_value.headers = multidict_headers
        mock_get.return_value.__aenter__.return_value.read = AsyncMock(
            return_value=bytes()
        )

    @patch("aiohttp.ClientSession.get")
    async def test_headers(self, mock_get: MagicMock) -> None:
        """Check setting and forwarding headers."""
        self._set_get_response(mock_get, 200, {"content-type": "application/json"})

        async with self.client.get(
            CONTENT_SCANNER_PATH, headers={"Host": "test2.org", "Other": "Stuff"}
        ) as resp:
            self.assertEqual(resp.status, 200)
            mock_get.assert_called_once()
            self.assertEqual(mock_get.call_args.args, (BASE_URL + MEDIA_PATH,))
            headers = mock_get.call_args.kwargs["headers"]
            self.assertEqual(len(headers), 2)
            self.assertEqual(headers.getall("Host"), ["test2.org"])
            self.assertEqual(headers.getall("Key"), ["Value"])
