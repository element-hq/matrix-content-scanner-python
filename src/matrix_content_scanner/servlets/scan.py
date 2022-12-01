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
from typing import TYPE_CHECKING, Optional, Tuple

from aiohttp import web

from matrix_content_scanner.servlets import get_media_metadata_from_request, web_handler
from matrix_content_scanner.utils.errors import FileDirtyError
from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class ScanHandler:
    def __init__(self, content_scanner: "MatrixContentScanner"):
        self._scanner = content_scanner.scanner
        self._crypto_handler = content_scanner.crypto_handler

    async def _scan_and_format(
        self,
        media_path: str,
        metadata: Optional[JsonDict] = None,
    ) -> Tuple[int, JsonDict]:
        try:
            await self._scanner.scan_file(media_path, metadata)
        except FileDirtyError as e:
            res = {"clean": False, "info": e.info}
        else:
            res = {"clean": True, "info": "File is clean"}

        return 200, res

    @web_handler
    async def handle_plain(self, request: web.Request) -> Tuple[int, JsonDict]:
        """Handles GET requests to ../scan/serverName/mediaId"""
        media_path = request.match_info["media_path"]
        return await self._scan_and_format(media_path)

    @web_handler
    async def handle_encrypted(self, request: web.Request) -> Tuple[int, JsonDict]:
        """Handles GET requests to ../scan_encrypted"""
        media_path, metadata = await get_media_metadata_from_request(
            request, self._crypto_handler
        )
        return await self._scan_and_format(media_path, metadata)
