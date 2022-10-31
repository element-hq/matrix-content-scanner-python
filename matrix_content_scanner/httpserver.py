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
import logging
from typing import TYPE_CHECKING

from twisted.web.resource import Resource
from twisted.web.server import Site

from matrix_content_scanner.servlets.download import (
    DownloadEncryptedServlet,
    DownloadServlet,
)
from matrix_content_scanner.servlets.public_key import PublicKeyServlet
from matrix_content_scanner.servlets.scan import ScanEncryptedServlet, ScanServlet
from matrix_content_scanner.servlets.thumbnail import ThumbnailServlet

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


class HTTPServer:
    def __init__(self, mcs: "MatrixContentScanner"):
        self._mcs = mcs
        self._bind_address = mcs.config.web.host
        self._bind_port = mcs.config.web.port

        root = self._build_resource_tree()
        self._site = Site(root)

    def _build_resource_tree(self) -> Resource:
        """Creates a resource tree with all the servlets.

        Returns:
            The root resource with the servlets attached to it.
        """
        root = Resource()
        matrix = Resource()
        media_proxy = Resource()
        unstable = Resource()

        root.putChild(b"_matrix", matrix)
        matrix.putChild(b"media_proxy", media_proxy)
        media_proxy.putChild(b"unstable", unstable)

        unstable.putChild(b"scan", ScanServlet(self._mcs))
        unstable.putChild(b"scan_encrypted", ScanEncryptedServlet(self._mcs))
        unstable.putChild(b"download", DownloadServlet(self._mcs))
        unstable.putChild(b"download_encrypted", DownloadEncryptedServlet(self._mcs))
        unstable.putChild(b"thumbnail", ThumbnailServlet(self._mcs))
        unstable.putChild(b"public_key", PublicKeyServlet(self._mcs))

        return root

    def start(self) -> None:
        """Starts the HTTP server."""
        logger.info("Starting listener on %s:%d", self._bind_address, self._bind_port)

        self._mcs.reactor.listenTCP(
            interface=self._bind_address,
            port=self._bind_port,
            factory=self._site,
            backlog=50,
        )
