# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from matrix_content_scanner.httpserver import HTTPServer

from tests.testutils import get_content_scanner


class HealthEndpointTestCase(AioHTTPTestCase):
    async def get_application(self) -> web.Application:
        return HTTPServer(get_content_scanner())._app

    async def test_health(self) -> None:
        """Tests that the health endpoint responds with 200 OK."""
        async with self.client.get("/health") as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(await resp.text(), "OK")
