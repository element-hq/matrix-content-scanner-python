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

from matrix_content_scanner.servlets import _BytesResponse, web_handler

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class ThumbnailHandler:
    def __init__(self, content_scanner: "MatrixContentScanner"):
        self._scanner = content_scanner.scanner

    @web_handler
    async def handle_thumbnail(
        self, request: web.Request
    ) -> Tuple[int, _BytesResponse]:
        """Handles GET requests to .../thumbnail/serverName/mediaId"""
        media_path = request.match_info["media_path"]

        media = await self._scanner.scan_file(
            media_path=media_path,
            thumbnail_params=request.query,
        )

        return 200, _BytesResponse(
            headers=media.response_headers,
            content=media.content,
        )
