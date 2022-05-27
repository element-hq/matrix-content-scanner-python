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
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Optional, Tuple

from twisted.web.http import Request

# The serverName/mediaId path of the media.
media_path: ContextVar[str] = ContextVar("media_path")
# The request being performed (download, thumbnail, scan, etc).
request_type: ContextVar[str] = ContextVar("request_type")

if TYPE_CHECKING:
    # We need to do this because mypy considers LoggerAdapter to be a generic, but it's
    # not the case at runtime on Python < 3.11.
    # See https://github.com/python/typeshed/issues/7855
    _LoggerAdapter = logging.LoggerAdapter[logging.Logger]
else:
    _LoggerAdapter = logging.LoggerAdapter


class ContextLoggingAdapter(_LoggerAdapter):
    """A logging adapter that reads from ContextVars to add the media path and request
    type to a logging record.
    """

    def process(self, msg: str, kwargs: Any) -> Tuple[str, Any]:
        kwargs.setdefault("extra", {})["media_path"] = _maybe_get_contextvar(media_path)
        kwargs.setdefault("extra", {})["request_type"] = _maybe_get_contextvar(
            request_type
        )

        return msg, kwargs


def _maybe_get_contextvar(var: ContextVar[str]) -> Optional[str]:
    """Tries to read from the given ContextVar without raising an exception if the
    ContextVar isn't set.

    Args:
        var: The ContextVar to read from.

    Returns:
        The ContextVar's value if set, otherwise None.
    """
    try:
        return var.get()
    except LookupError:
        pass

    return None


def getLogger(name: str) -> ContextLoggingAdapter:
    """Returns a logger for the given name wrapped in a ContextLoggingAdapter.

    This function is named using camel case as opposed to snake case (which is used for
    all other functions and methods in this project) so it can be used as a drop-in
    replacement for `logging.getLogger`.

    Args:
        name: The logger's name.

    Returns:
        The wrapped logger.
    """
    return ContextLoggingAdapter(logging.getLogger(name), None)


def set_context_from_request(request: Request) -> None:
    """Set the media_path and request_type ContextVars from the given request if possible.

    Args:
        request: The request to set the context from.
    """
    assert request.path is not None
    path = request.path.decode("utf-8")

    # We're only interested in the bit after /_matrix/media_proxy/unstable
    parts = path.split("/")[4:]
    request_type.set(parts[0])

    # If we have more than one part, then we likely have the media path as well in the
    # request's path.
    if len(parts) == 3:
        media_path.set("/".join(parts[1:]))


def set_media_path_in_context(v: str) -> None:
    """Sets the media_path ContextVar to the given value.

    Args:
        v: The value to set the ContextVar.
    """
    media_path.set(v)
