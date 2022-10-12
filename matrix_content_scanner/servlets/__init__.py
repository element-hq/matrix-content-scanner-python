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
import abc
import json
import logging
from typing import Any, Awaitable, Callable, Optional, Tuple

from twisted.internet import defer
from twisted.web.http import Request
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from matrix_content_scanner import logutils
from matrix_content_scanner.crypto import CryptoHandler
from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.encrypted_file_metadata import (
    validate_encrypted_file_metadata,
)
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict

logger = logging.getLogger(__name__)


class _AsyncResource(Resource, metaclass=abc.ABCMeta):
    def render(self, request: Request) -> int:
        """This gets called by twisted every time someone sends us a request."""
        defer.ensureDeferred(self._async_render(request))
        return NOT_DONE_YET

    async def _async_render(self, request: Request) -> None:
        """Processes the incoming request asynchronously and handles errors."""
        # Treat HEAD requests as GET requests.
        request_method = request.method.decode("ascii")
        if request_method == "HEAD":
            request_method = "GET"

        # Set the request type in the logging context.
        assert request.path is not None
        parts = request.path.split(b"/")
        # Paths in the content scanner API use the form
        # "/_matrix/media_proxy/unstable/{requestType}/...", so the request type is at
        # index 4 in the parts.
        logutils.set_request_type_in_context(parts[4].decode("ascii"))

        # Try to find a handler for this request.
        method_handler: Callable[[Request], Awaitable[Tuple[int, Any]]] = getattr(
            self, "on_%s" % (request_method,), None
        )  # type: ignore[assignment]
        if not method_handler:
            # If we don't have a handler, respond with a 404.
            self._send_error(
                request=request,
                status=404,
                reason=ErrCode.NOT_FOUND,
                info="Route not found",
            )
            return

        try:
            # We have a request handler: call it and send the response.
            code, response = await method_handler(request)
            self._send_response(request, code, response)
        except ContentScannerRestError as e:
            # If we get a REST error, use it to generate an error response.
            self._send_error(
                request=request,
                status=e.http_status,
                reason=e.reason,
                info=e.info,
            )
        except Exception as e:
            # Otherwise, just treat it as an unknown server error.
            logger.exception(e)
            self._send_error(
                request=request,
                status=500,
                reason=ErrCode.UNKNOWN,
                info="Internal Server Error",
            )

    def _send_error(
        self, request: Request, status: int, reason: ErrCode, info: str
    ) -> None:
        """Send an error response with the provided parameters.

        Args:
            request: The request to respond to.
            status: The HTTP status to respond with.
            reason: The error code to include in the response.
            info: Additional human-readable info to include in the response.
        """
        request.setResponseCode(status)
        request.setHeader("Content-Type", "application/json")
        res = _to_json_bytes({"reason": str(reason), "info": info})
        request.write(res)
        request.finish()

    @abc.abstractmethod
    def _send_response(
        self,
        request: Request,
        status: int,
        response_content: Any,
    ) -> None:
        """Responds to the request with the given content.

        Args:
            request: The request to respond to.
            status: The HTTP status to respond to the request with.
            response_content: The content to respond with.
        """
        raise NotImplementedError()


class JsonResource(_AsyncResource):
    """A resource that will call `self._async_on_<METHOD>` on new requests,
    formatting responses and errors as JSON.
    """

    def _send_response(
        self, request: Request, status: int, response_content: Any
    ) -> None:
        """Implements _AsyncResource._send_response. Expects response_content to be
        serialisable into JSON.
        """
        request.setResponseCode(status)
        request.setHeader("Content-Type", "application/json")
        request.write(_to_json_bytes(response_content))
        request.finish()


def _to_json_bytes(content: JsonDict) -> bytes:
    """Converts a dict into JSON and encodes it to bytes."""
    return json.dumps(content).encode("UTF-8")


class BytesResource(_AsyncResource):
    """A resource that will call `self._async_on_<METHOD>` on new requests,
    formatting responses and errors as HTML.
    """

    def _send_response(
        self, request: Request, status: int, response_content: Any
    ) -> None:
        """Implements _AsyncResource._send_response. Expects the child class to have
        already set the content type header. Also expects response_content to be bytes.
        """
        assert isinstance(response_content, bytes)
        request.setResponseCode(status)
        request.write(response_content)
        request.finish()


def get_media_metadata_from_request(
    request: Request, crypto_handler: CryptoHandler
) -> Tuple[str, JsonDict]:
    """Extracts, optionally decrypts, and validates encrypted file metadata from a
    request body.

    Args:
        request: The request to extract the data from.
        crypto_handler: The crypto handler to use if we need to decrypt an Olm-encrypted
            body.

    Raises:
        ContentScannerRestError(400) if the request's body is None or if the metadata
            didn't pass schema validation.
    """
    if request.content is None:
        raise ContentScannerRestError(
            400,
            ErrCode.MALFORMED_JSON,
            "No content in request body",
        )

    body = request.content.read().decode("ascii")

    metadata = _metadata_from_body(body, crypto_handler)

    validate_encrypted_file_metadata(metadata)

    # Get the media path and set the context.
    url = metadata["file"]["url"]
    media_path = url[len("mxc://") :]
    logutils.set_media_path_in_context(media_path)

    return media_path, metadata


def _metadata_from_body(body: str, crypto_handler: CryptoHandler) -> JsonDict:
    """Parse the given body as JSON, and decrypts it if needed.

    Args:
        body: The body to parse.
        crypto_handler: The crypto handler to use if we need to decrypt an Olm-encrypted
            body.

    Returns:
        The parsed and decrypted file metadata.

    Raises:
        ContentScannerRestError(400) if the body isn't valid JSON or isn't a dictionary.
    """
    # Try to parse the raw body.
    try:
        parsed_body = json.loads(body)
    except json.decoder.JSONDecodeError as e:
        raise ContentScannerRestError(400, ErrCode.MALFORMED_JSON, str(e))

    # Every POST request body in the API implemented by the content scanner is a dict.
    if not isinstance(parsed_body, dict):
        raise ContentScannerRestError(
            400,
            ErrCode.MALFORMED_JSON,
            "Body must be a dictionary",
        )

    # Check if the metadata is encrypted, if not then the metadata is in clear text in
    # the body so just return it.
    encrypted_body: Optional[JsonDict] = parsed_body.get("encrypted_body")
    if encrypted_body is None:
        return parsed_body

    # If it is encrypted, decrypt it and return the decrypted version.
    return crypto_handler.decrypt_body(
        ciphertext=encrypted_body["ciphertext"],
        mac=encrypted_body["mac"],
        ephemeral=encrypted_body["ephemeral"],
    )
