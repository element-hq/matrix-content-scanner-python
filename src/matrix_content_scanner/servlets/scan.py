#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from typing import TYPE_CHECKING, Optional, Tuple

from aiohttp import web
from multidict import MultiMapping

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
        req_headers: MultiMapping[str],
        metadata: Optional[JsonDict] = None,
        auth_header: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        try:
            await self._scanner.scan_file(
                media_path, req_headers, metadata, auth_header=auth_header
            )
        except FileDirtyError as e:
            res = {"clean": False, "info": e.info}
        else:
            res = {"clean": True, "info": "File is clean"}

        return 200, res

    @web_handler
    async def handle_plain(self, request: web.Request) -> Tuple[int, JsonDict]:
        """Handles GET requests to ../scan/serverName/mediaId"""
        media_path = request.match_info["media_path"]
        return await self._scan_and_format(
            media_path,
            request.headers,
            auth_header=request.headers.get("Authorization"),
        )

    @web_handler
    async def handle_encrypted(self, request: web.Request) -> Tuple[int, JsonDict]:
        """Handles GET requests to ../scan_encrypted"""
        media_path, metadata = await get_media_metadata_from_request(
            request, self._crypto_handler
        )
        return await self._scan_and_format(
            media_path,
            request.headers,
            metadata,
            auth_header=request.headers.get("Authorization"),
        )
