#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from typing import TYPE_CHECKING, Optional, Tuple

from aiohttp import web
from matrix_common.types.mxc_uri import MXCUri
from multidict import MultiMapping

from matrix_content_scanner.servlets import (
    _BytesResponse,
    get_media_metadata_from_request,
    get_mxc_uri_from_request,
    web_handler,
)
from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


class DownloadHandler:
    def __init__(self, content_scanner: "MatrixContentScanner"):
        self._scanner = content_scanner.scanner
        self._crypto_handler = content_scanner.crypto_handler

    async def _scan(
        self,
        mxc_uri: MXCUri,
        req_headers: MultiMapping[str],
        metadata: Optional[JsonDict] = None,
        auth_header: Optional[str] = None,
    ) -> Tuple[int, _BytesResponse]:
        media = await self._scanner.scan_file(
            mxc_uri, req_headers, metadata, auth_header=auth_header
        )

        return 200, _BytesResponse(
            headers=media.response_headers,
            content=media.content,
        )

    @web_handler
    async def handle_plain(self, request: web.Request) -> Tuple[int, _BytesResponse]:
        """Handles GET requests to ../download/serverName/mediaId"""
        mxc_uri = get_mxc_uri_from_request(request)
        return await self._scan(
            mxc_uri,
            request.headers,
            auth_header=request.headers.get("Authorization"),
        )

    @web_handler
    async def handle_encrypted(
        self, request: web.Request
    ) -> Tuple[int, _BytesResponse]:
        """Handles POST requests to ../download_encrypted"""
        mxc_uri, metadata = await get_media_metadata_from_request(
            request, self._crypto_handler
        )

        return await self._scan(
            mxc_uri,
            request.headers,
            metadata,
            auth_header=request.headers.get("Authorization"),
        )
