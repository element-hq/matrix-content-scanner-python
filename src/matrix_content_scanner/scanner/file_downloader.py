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
import json
import logging
import urllib.parse
from http import HTTPStatus
from typing import TYPE_CHECKING, Dict, Optional, Tuple

import aiohttp
from multidict import CIMultiDictProxy, MultiDictProxy

from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import (
    ContentScannerRestError,
    WellKnownDiscoveryError,
)
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
        self._well_known_cache: Dict[str, Optional[str]] = {}
        self._proxy_url = mcs.config.download.proxy
        self._headers = mcs.config.download.additional_headers

    async def download_file(
        self,
        media_path: str,
        thumbnail_params: Optional[MultiDictProxy[str]] = None,
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
            ContentScannerRestError: The file was not found or could not be downloaded due
                to an error on the remote homeserver's side.
        """
        url = await self._build_https_url(media_path)

        # Attempt to retrieve the file at the generated URL.
        try:
            file = await self._get_file_content(url, thumbnail_params)
        except _PathNotFoundException:
            # If the file could not be found, it might be because the homeserver hasn't
            # been upgraded to a version that supports Matrix v1.1 endpoints yet, so try
            # again with an r0 endpoint.
            logger.info("File not found, trying legacy r0 path")

            url = await self._build_https_url(media_path, endpoint_version="r0")

            try:
                file = await self._get_file_content(url, thumbnail_params)
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
    ) -> str:
        """Turn a `server_name/media_id` path into an https:// one we can use to fetch
        the media.

        Note that if `base_homeserver_url` is set to an http URL, it will not be turned
        into an https one.

        Args:
            media_path: The media path to translate.
            endpoint_version: The version of the download endpoint to use. As of Matrix
                v1.1, this is either "v3" or "r0".

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
            base_url = None

            try:
                base_url = await self._discover_via_well_known(server_name)
            except WellKnownDiscoveryError as e:
                # We don't catch ContentScannerRestErrors here because if one makes its
                # way up here then it likely means that trying to reach https://server_name
                # failed, in which case we're unlikely to be able to reach it again when
                # downloading the file, so we let the error escalate.
                logger.info("Failed to discover server via well-known: %s", e)

            if base_url is None:
                # base_url might be None if either .well-known discovery failed, or we
                # didn't find a .well-known file.
                base_url = "https://" + server_name

        prefix = self.MEDIA_DOWNLOAD_PREFIX

        # Build the full URL.
        path_prefix = prefix % endpoint_version
        url = "%s/%s/%s/%s" % (
            base_url,
            path_prefix,
            urllib.parse.quote(server_name),
            urllib.parse.quote(media_id),
        )

        return url

    async def _get_file_content(
        self,
        url: str,
        thumbnail_params: Optional[MultiDictProxy[str]],
    ) -> MediaDescription:
        """Retrieve the content of the file at a given URL.

        Args:
            url: The URL to query.
            thumbnail_params: Query parameters used if the request is for a thumbnail.

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
        code, body, headers = await self._get(url, query=thumbnail_params)

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
        content_type_headers = headers.getall("content-type", None)
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

    async def _discover_via_well_known(self, domain: str) -> Optional[str]:
        """Try to discover the base URL for the given domain via .well-known client
        discovery.

        Args:
            domain: The domain to discover the base URL for.

        Returns:
            The base URL to use, or None if no .well-known client file exist for this
            domain.

        Raises:
            WellKnownDiscoveryError if an error happened during the discovery attempt.
        """
        # Check if we already have a result cached, and if so return with it straight
        # away.
        if domain in self._well_known_cache:
            logger.info("Fetching .well-known discovery result from cache")
            return self._well_known_cache[domain]

        # Attempt to download the .well-known file.
        try:
            url = f"https://{domain}/.well-known/matrix/client"
            code, body, _ = await self._get(url)
        except ContentScannerRestError:
            raise WellKnownDiscoveryError(f"Failed to reach web server at {domain}")

        if code != 200:
            if code == 404:
                # If the response status is 404, then the homeserver hasn't set up
                # .well-known discovery, in which case we tell the caller that there's
                # no base URL to use rather than raising an error.
                # The difference is that we want to cache this result here, but we don't
                # want to do that when the discovery fails due to an incorrectly set up
                # file or an unavailable homeserver, which might be fixed later on.
                logger.info(
                    ".well-known discover has not been set up for this homeserver"
                )
                self._well_known_cache[domain] = None
                return None

            raise WellKnownDiscoveryError(
                f"Server responded with non-200 status {code}"
            )

        # Try to parse the JSON content.
        try:
            parsed_body = json.loads(body)
        except json.decoder.JSONDecodeError as e:
            raise WellKnownDiscoveryError(e)

        # Check if the parsed content has a base URL in the right place.
        try:
            base_url: str = parsed_body["m.homeserver"]["base_url"]
        except (KeyError, TypeError):
            # We might get a KeyError if we're trying to reach a key that doesn't exist,
            # and we might get a TypeError if parsed_body or parsed_body["m.homeserver"]
            # isn't a dictionary.
            raise WellKnownDiscoveryError("Response did not include a usable URL")

        # Remove the trailing slash if there is one.
        if base_url.endswith("/"):
            base_url = base_url[:-1]

        # Check if the base URL is one for a working homeserver.
        url = base_url + "/_matrix/client/versions"
        try:
            code, _, _ = await self._get(url)
        except ContentScannerRestError:
            raise WellKnownDiscoveryError(
                "Base URL does not seem to point to a working homeserver"
            )

        if code != 200:
            raise WellKnownDiscoveryError(
                "Base URL does not seem to point to a working homeserver"
            )

        # Cache and return the result.
        self._well_known_cache[domain] = base_url
        return base_url

    async def _get(
        self,
        url: str,
        query: Optional[MultiDictProxy[str]] = None,
    ) -> Tuple[int, bytes, CIMultiDictProxy[str]]:
        """Sends a GET request to the provided URL.

        Args:
            url: The URL to send requests to.
            query: Optional parameters to use in the request's query string.

        Returns:
            The HTTP status code, body and headers the remote server responded with.

        Raises:
            ContentScannerRestError(502) if the request failed (if the remote server
                timed out or refused the connection, etc.).
        """
        try:
            logger.info("Sending GET request to %s", url)
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    proxy=self._proxy_url,
                    headers=self._headers,
                    params=query,
                ) as resp:
                    return resp.status, await resp.read(), resp.headers

        except Exception as e:
            logger.error(e)
            raise ContentScannerRestError(
                HTTPStatus.BAD_GATEWAY,
                ErrCode.REQUEST_FAILED,
                "Failed to reach the remote server",
            )
