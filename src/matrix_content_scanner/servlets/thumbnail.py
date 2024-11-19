#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only
# Please see LICENSE in the repository root for full details.
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
