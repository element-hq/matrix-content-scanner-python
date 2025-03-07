#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
import logging
from typing import TYPE_CHECKING, Awaitable, Callable

from aiohttp import web

from matrix_content_scanner.servlets.download import DownloadHandler
from matrix_content_scanner.servlets.public_key import PublicKeyHandler
from matrix_content_scanner.servlets.scan import ScanHandler
from matrix_content_scanner.servlets.thumbnail import ThumbnailHandler

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)

_MEDIA_PATH_REGEXP = r"/{media_path:.+}"

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Origin, X-Requested-With, Content-Type, Accept, Authorization",
}


@web.middleware
async def simple_cors_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """A simple aiohttp middleware that adds CORS headers to responses, and handles
    OPTIONS requests.

    Args:
        request: The request to handle.
        handler: The handler for this request.

    Returns:
        A response with CORS headers.
    """
    if request.method == "OPTIONS":
        # We don't register routes for OPTIONS requests, therefore the handler we're given
        # in this case just raises a 405 Method Not Allowed status using an exception.
        # Because we actually want to return a 200 OK with additional headers, we ignore
        # the handler and just return a new response.
        response = web.StreamResponse(
            status=200,
            headers=_CORS_HEADERS,
        )
        return response

    # Run the request's handler and append CORS headers to it.
    response = await handler(request)
    response.headers.update(_CORS_HEADERS)
    return response


@web.middleware
async def json_errors_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """A simple aiohttp middleware that converts 404/405 errors into Matrix JSON error.

    Args:
        request: The request to handle.
        handler: The handler for this request.

    Returns:
        The original response OR a JSON error response.
    """
    # Run the request's handler and append CORS headers to it.
    try:
        return await handler(request)
    except (web.HTTPNotFound, web.HTTPMethodNotAllowed) as ex:
        # Return the proper JSON response.
        return web.json_response(
            {"errcode": "M_UNRECOGNIZED", "error": "Unrecognized request"},
            status=ex.status,
        )


class HTTPServer:
    def __init__(self, mcs: "MatrixContentScanner"):
        self._mcs = mcs
        self._bind_address = mcs.config.web.host
        self._bind_port = mcs.config.web.port

        self._app = self._build_app()

    def _build_app(self) -> web.Application:
        """Build the aiohttp app and attach all the handlers to it.

        Returns:
            The built aiohttp application.
        """
        # First we build an application with all routes defined on the root path.
        app = web.Application()

        scan_handler = ScanHandler(self._mcs)
        download_handler = DownloadHandler(self._mcs)
        thumbnail_handler = ThumbnailHandler(self._mcs)
        public_key_handler = PublicKeyHandler(self._mcs)

        app.add_routes(
            [
                web.get("/scan" + _MEDIA_PATH_REGEXP, scan_handler.handle_plain),
                web.post("/scan_encrypted", scan_handler.handle_encrypted),
                web.get(
                    "/download" + _MEDIA_PATH_REGEXP, download_handler.handle_plain
                ),
                web.post("/download_encrypted", download_handler.handle_encrypted),
                web.get(
                    "/thumbnail" + _MEDIA_PATH_REGEXP,
                    thumbnail_handler.handle_thumbnail,
                ),
                web.get(
                    "/public_key",
                    public_key_handler.handle_public_key,
                ),
            ]
        )

        # Then we create a root application, and define the app we previously created as
        # a subapp on the base path for the content scanner API.
        root = web.Application(
            # Apply middlewares. This will also apply to subapps.
            middlewares=[
                # Handle trailing slashes.
                web.normalize_path_middleware(),
                # Handler CORS.
                simple_cors_middleware,
                # Convert unknown routes/methods into JSON errors.
                json_errors_middleware,
            ],
        )
        root.add_subapp("/_matrix/media_proxy/unstable", app)

        return root

    def start(self) -> None:
        """Start an aiohttp server serving the content scanner API."""
        logger.info("Starting listener on %s:%d", self._bind_address, self._bind_port)
        web.run_app(
            app=self._app,
            host=self._bind_address,
            port=self._bind_port,
            print=None,
        )
