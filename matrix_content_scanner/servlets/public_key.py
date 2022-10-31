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
from typing import TYPE_CHECKING, Tuple

from twisted.web.http import Request

from matrix_content_scanner.servlets import JsonResource
from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class PublicKeyServlet(JsonResource):
    """Handles GET requests to .../public_key"""

    def __init__(self, content_scanner: "MatrixContentScanner") -> None:
        super().__init__()
        self._crypto_handler = content_scanner.crypto_handler

    async def on_GET(self, request: Request) -> Tuple[int, JsonDict]:
        return 200, {"public_key": self._crypto_handler.public_key}
