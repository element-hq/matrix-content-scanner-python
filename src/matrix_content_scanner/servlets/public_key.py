#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from typing import TYPE_CHECKING, Tuple

from aiohttp import web

from matrix_content_scanner.servlets import web_handler
from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class PublicKeyHandler:
    def __init__(self, content_scanner: "MatrixContentScanner") -> None:
        self._crypto_handler = content_scanner.crypto_handler

    @web_handler
    async def handle_public_key(self, request: web.Request) -> Tuple[int, JsonDict]:
        """Handles GET requests to .../public_key"""
        return 200, {"public_key": self._crypto_handler.public_key}
