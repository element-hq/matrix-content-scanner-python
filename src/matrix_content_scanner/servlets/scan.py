#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
from typing import TYPE_CHECKING, Optional, Tuple

from aiohttp import web
from matrix_common.types.mxc_uri import MXCUri
from multidict import MultiMapping

from matrix_content_scanner.servlets import (
    get_media_metadata_from_request,
    get_mxc_uri_from_request,
    web_handler,
)
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
        mxc_uri: MXCUri,
        req_headers: MultiMapping[str],
        metadata: Optional[JsonDict] = None,
        auth_header: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        try:
            await self._scanner.scan_file(
                mxc_uri, req_headers, metadata, auth_header=auth_header
            )
        except FileDirtyError as e:
            res = {"clean": False, "info": e.info}
        else:
            res = {"clean": True, "info": "File is clean"}

        return 200, res

    @web_handler
    async def handle_plain(self, request: web.Request) -> Tuple[int, JsonDict]:
        """Handles GET requests to ../scan/serverName/mediaId"""
        try:
            mxc_uri = get_mxc_uri_from_request(request)
        except FileDirtyError as e:
            return 200, {"clean": False, "info": e.info}

        return await self._scan_and_format(
            mxc_uri,
            request.headers,
            auth_header=request.headers.get("Authorization"),
        )

    @web_handler
    async def handle_encrypted(self, request: web.Request) -> Tuple[int, JsonDict]:
        """Handles GET requests to ../scan_encrypted"""
        mxc_uri, metadata = await get_media_metadata_from_request(
            request, self._crypto_handler
        )
        return await self._scan_and_format(
            mxc_uri,
            request.headers,
            metadata,
            auth_header=request.headers.get("Authorization"),
        )
