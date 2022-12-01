#  Copyright 2022 New Vector Ltd
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
