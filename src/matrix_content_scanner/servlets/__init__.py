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
import functools
import json
import logging
from typing import Awaitable, Callable, Dict, Optional, Tuple, TypeVar, Union

import attr
from aiohttp import web
from multidict import CIMultiDictProxy

from matrix_content_scanner import logutils
from matrix_content_scanner.crypto import CryptoHandler
from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.encrypted_file_metadata import (
    validate_encrypted_file_metadata,
)
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict

logger = logging.getLogger(__name__)

_next_request_seq = 0

_Handler = TypeVar("_Handler")


@attr.s(auto_attribs=True, frozen=True, slots=True)
class _BytesResponse:
    """A binary response, and the headers to send back to the client alongside it."""

    headers: CIMultiDictProxy[str]
    content: bytes


def web_handler(
    func: Callable[
        [_Handler, web.Request], Awaitable[Tuple[int, Union[JsonDict, _BytesResponse]]]
    ],
) -> Callable[[_Handler, web.Request], Awaitable[web.Response]]:
    """Decorator that adds a wrapper to the given web handler method, which turns its
    return value into an aiohttp Response, and handles errors.

    Args:
        func: The function to wrap.

    Returns:
        The wrapper to run for this function.
    """

    def handle_error(status: int, reason: ErrCode, info: Optional[str]) -> web.Response:
        """Turns an error with the given parameters into an aiohttp Response.

        Args:
            status: The HTTP status code.
            reason: The error code to include in the response's JSON body.
            info: Optional extra info to include in the response's JSON body.
        """
        # Write the reason for the error into the response body, and add some extra info
        # if we have any.
        res_body: JsonDict = {"reason": reason}
        if info is not None:
            res_body["info"] = info

        res = _to_json_bytes(res_body)

        return web.Response(
            status=status,
            content_type="application/json",
            body=res,
        )

    @functools.wraps(func)
    async def wrapper(self: _Handler, request: web.Request) -> web.Response:
        """Run the wrapped method, and turn the return value into an aiohttp Response.

        If the wrapped method raises an exception, turn that into an aiohttp Response
        as well.

        Args:
            self: The object the wrapped method belongs to.
            request: The aiohttp Request to process.
        """
        # Set the request ID in the logging context, and increment the sequence for the
        # next request.
        global _next_request_seq
        request_id = f"{request.method}-{_next_request_seq}"
        logutils.set_request_id_in_context(request_id)
        _next_request_seq += 1

        # Check that the path is correct.
        if not request.path.startswith("/_matrix/media_proxy/unstable"):
            return handle_error(
                status=400,
                reason=ErrCode.UNKNOWN,
                info="Invalid path",
            )

        try:
            status, res = await func(self, request)

            # Set the response and headers according to the return value. If the handler
            # didn't return with a bytes response (in which it is responsible for
            # providing the headers, including the content-type one), default to json.
            headers: Union[Dict[str, str], CIMultiDictProxy[str]]
            if isinstance(res, _BytesResponse):
                raw_res = res.content
                headers = res.headers
            else:
                raw_res = _to_json_bytes(res)
                headers = {"content-type": "application/json"}

            return web.Response(
                status=status,
                body=raw_res,
                headers=headers,
            )
        except ContentScannerRestError as e:
            # If we get a REST error, use it to generate an error response.
            return handle_error(
                status=e.http_status,
                reason=e.reason,
                info=e.info,
            )
        except Exception as e:
            # Otherwise, just treat it as an unknown server error.
            logger.exception(e)
            return handle_error(
                status=500,
                reason=ErrCode.UNKNOWN,
                info="Internal Server Error",
            )

    return wrapper


def _to_json_bytes(content: JsonDict) -> bytes:
    """Converts a dict into JSON and encodes it to bytes."""
    return json.dumps(content).encode("UTF-8")


async def get_media_metadata_from_request(
    request: web.Request,
    crypto_handler: CryptoHandler,
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

    try:
        body = await request.json()
    except json.decoder.JSONDecodeError as e:
        raise ContentScannerRestError(400, ErrCode.MALFORMED_JSON, str(e))

    metadata = _metadata_from_body(body, crypto_handler)

    validate_encrypted_file_metadata(metadata)

    # Get the media path.
    url = metadata["file"]["url"]
    media_path = url[len("mxc://") :]

    return media_path, metadata


def _metadata_from_body(body: JsonDict, crypto_handler: CryptoHandler) -> JsonDict:
    """Parse the given body as JSON, and decrypts it if needed.

    Args:
        body: The body, parsed as JSON.
        crypto_handler: The crypto handler to use if we need to decrypt an Olm-encrypted
            body.

    Returns:
        The parsed and decrypted file metadata.

    Raises:
        ContentScannerRestError(400) if the body isn't valid JSON or isn't a dictionary.
    """
    # Every POST request body in the API implemented by the content scanner is a dict.
    if not isinstance(body, dict):
        raise ContentScannerRestError(
            400,
            ErrCode.MALFORMED_JSON,
            "Body must be a dictionary",
        )

    # Check if the metadata is encrypted, if not then the metadata is in clear text in
    # the body so just return it.
    encrypted_body: Optional[JsonDict] = body.get("encrypted_body")
    if encrypted_body is None:
        return body

    # If it is encrypted, decrypt it and return the decrypted version.
    return crypto_handler.decrypt_body(
        ciphertext=encrypted_body["ciphertext"],
        mac=encrypted_body["mac"],
        ephemeral=encrypted_body["ephemeral"],
    )
