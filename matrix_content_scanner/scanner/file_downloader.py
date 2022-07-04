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
import json
import logging
import urllib.parse
from http import HTTPStatus
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS, ProxyAgent, readBody
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent, IResponse

from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import MediaDescription

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner

logger = logging.getLogger(__name__)


class _PathNotFoundException(Exception):
    """An exception raised to signal that a URL could not be found on the remote
    homeserver.
    """

    pass


class FileDownloader:
    MEDIA_DOWNLOAD_PREFIX = "_matrix/media/%s/download"
    MEDIA_THUMBNAIL_PREFIX = "_matrix/media/%s/thumbnail"

    def __init__(self, mcs: "MatrixContentScanner"):
        self._base_url = mcs.config.download.base_homeserver_url
        self._agent = self._get_agent(mcs)
        self._well_known_cache: Dict[str, Optional[str]] = {}

        self._headers: Optional[Headers] = None
        if mcs.config.download.additional_headers is not None:
            self._headers = Headers()
            for name, value in mcs.config.download.additional_headers.items():
                self._headers.addRawHeader(name, value)

    def _get_agent(self, mcs: "MatrixContentScanner") -> IAgent:
        """Instantiates the Twisted agent to use to make requests.

        This will be a ProxyAgent if a proxy is configured, and a basic Agent otherwise.

        Args:
            mcs: The content scanner instance to use to build the agent.

        Returns:
            The agent to use.
        """
        if mcs.config.download.proxy is None:
            return Agent(mcs.reactor)

        proxy_url = urllib.parse.urlparse(mcs.config.download.proxy.encode("utf-8"))

        endpoint = HostnameEndpoint(mcs.reactor, proxy_url.hostname, proxy_url.port)
        if proxy_url.scheme == b"https":
            policy = BrowserLikePolicyForHTTPS()
            endpoint = wrapClientTLS(
                policy.creatorForNetloc(proxy_url.hostname, proxy_url.port),
                endpoint,
            )

        return ProxyAgent(endpoint, mcs.reactor)

    async def download_file(
        self,
        media_path: str,
        thumbnail_params: Optional[Dict[str, List[str]]] = None,
    ) -> MediaDescription:
        """Retrieve the file with the given `server_name/media_id` path, and stores it on
        disk.

        Args:
            media_path: The path identifying the media to retrieve.
            thumbnail_params: If present, then we want to request and scan a thumbnail
                generated with the provided parameters instead of the full media.

        Returns:
            A description of the file (including its full content).

        Raises:
            ContentScannerRestError: The file was not found or could not be downloaded due to an
                error on the remote homeserver's side.
        """
        url = await self._build_https_url(media_path, thumbnail_params=thumbnail_params)

        # Attempt to retrieve the file at the generated URL.
        try:
            file = await self._get_file_content(url)
        except _PathNotFoundException:
            # If the file could not be found, it might be because the homeserver hasn't
            # been upgraded to a version that supports Matrix v1.1 endpoints yet, so try
            # again with an r0 endpoint.
            logger.info("File not found, trying legacy r0 path")

            url = await self._build_https_url(
                media_path, endpoint_version="r0", thumbnail_params=thumbnail_params
            )

            try:
                file = await self._get_file_content(url)
            except _PathNotFoundException:
                # If that still failed, raise an error.
                raise ContentScannerRestError(
                    http_status=HTTPStatus.BAD_GATEWAY,
                    reason=ErrCode.REQUEST_FAILED,
                    info="File not found",
                )

        return file

    async def _build_https_url(
        self,
        media_path: str,
        endpoint_version: str = "v3",
        thumbnail_params: Optional[Dict[str, List[str]]] = None,
    ) -> str:
        """Turn a `server_name/media_id` path into an https:// one we can use to fetch
        the media.

        Note that if `base_homeserver_url` is set to an http URL, it will not be turned
        into an https one.

        Args:
            media_path: The media path to translate.
            endpoint_version: The version of the download endpoint to use. As of Matrix
                v1.1, this is either "v3" or "r0".
            thumbnail_params: If present, then we want to request and scan a thumbnail
                generated with the provided parameters instead of the full media.

        Returns:
            An https URL to use. If `base_homeserver_url` is set in the config, this
            will be used as the base of the URL.
        """
        server_name, media_id = media_path.split("/")

        # Figure out what base URL to use. If one is specified in the configuration file,
        # use it, otherwise try to discover one using .well-known. If that fails, use the
        # server name with an HTTPS scheme.
        if self._base_url is not None:
            base_url = self._base_url
        else:
            base_url = "https://" + server_name

        prefix = self.MEDIA_DOWNLOAD_PREFIX
        query = None
        if thumbnail_params is not None:
            # If there are thumbnail generation parameters, then we want to generate a
            # thumbnail of the file, not download its full-sized version.
            prefix = self.MEDIA_THUMBNAIL_PREFIX

            # Reconstruct the query parameters provided by the client.
            query = ""
            for key, items in thumbnail_params.items():
                for item in items:
                    query += "%s=%s&" % (
                        urllib.parse.quote(key),
                        urllib.parse.quote(item),
                    )
            query = query[:-1]

        # Build the full URL.
        path_prefix = prefix % endpoint_version
        url = "%s/%s/%s/%s" % (
            base_url,
            path_prefix,
            urllib.parse.quote(server_name),
            urllib.parse.quote(media_id),
        )
        if query is not None:
            # If there are query parameters, append them to the URL.
            url += "?%s" % query

        return url

    async def _get_file_content(self, url: str) -> MediaDescription:
        """Retrieve the content of the file at a given URL.

        Args:
            url: The URL to query.

        Returns:
            A description of the file (including its full content).

        Raises:
            _PathNotFoundException: the server returned an error that can mean the path
                of the request wasn't understood, e.g. because we requested a v3 URL but
                the server only supports r0, or the media couldn't be found.
                We raise a separate error class in this case because if the error is due
                to a v3 vs r0 path we want to retry the request on the r0 path.
            ContentScannerRestError: the server returned a non-200 status which cannot
                meant that the path wasn't understood.
        """
        code, body, headers = await self._get(url)

        logger.info("Remote server responded with %d", code)

        # If the response isn't a 200 OK, raise.
        if 200 < code:
            logger.info("Response body: %s", body)
            # If the response is a 404 or an "unrecognised request" à la Synapse,
            # consider that we could not find the media, and that we should retry if this
            # request was directed at a v3 endpoint.
            if code == 400:
                try:
                    err = json.loads(body)
                    if err["errcode"] == "M_UNRECOGNIZED":
                        raise _PathNotFoundException
                except (json.decoder.JSONDecodeError, KeyError):
                    pass

            if code == 404:
                raise _PathNotFoundException

            raise ContentScannerRestError(
                HTTPStatus.BAD_GATEWAY,
                ErrCode.REQUEST_FAILED,
                "The remote server responded with an error",
            )

        # Check that we have the right amount of Content-Type headers (so we don't get
        # confused later when we try comparing it with the file's MIME type).
        content_type_headers = headers.getRawHeaders("content-type")
        if content_type_headers is None or len(content_type_headers) != 1:
            raise ContentScannerRestError(
                HTTPStatus.BAD_GATEWAY,
                ErrCode.REQUEST_FAILED,
                "The remote server responded with an invalid amount of Content-Type headers",
            )

        return MediaDescription(
            content_type=content_type_headers[0],
            content=body,
            response_headers=headers,
        )

    async def _get(self, url: str) -> Tuple[int, bytes, Headers]:
        """Sends a GET request to the provided URL.

        Args:
            url: The URL to send requests to.

        Returns:
            The HTTP status code, body and headers the remote server responded with.

        Raises:
            ContentScannerRestError(502) if the request failed (if the remote server
                timed out or refused the connection, etc.).
        """
        try:
            logger.info("Sending GET request to %s", url)
            resp: IResponse = await self._agent.request(
                b"GET",
                url.encode("ascii"),
                self._headers,
            )
        except Exception as e:
            logger.error(e)
            raise ContentScannerRestError(
                HTTPStatus.BAD_GATEWAY,
                ErrCode.REQUEST_FAILED,
                "Failed to reach the remote server",
            )

        return resp.code, await readBody(resp), resp.headers
