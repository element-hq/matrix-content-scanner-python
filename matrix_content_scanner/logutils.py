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
from typing import Any

from twisted.web.http import Request

# The serverName/mediaId path of the media.
media_path: ContextVar[str] = ContextVar("media_path")
# The request being performed (download, thumbnail, scan, etc).
request_type: ContextVar[str] = ContextVar("request_type")


def setup_custom_factory() -> None:
    """Generates a new record factory, chained to the current factory, and sets it as the
    new default record factory.

    The new factory adds attributes for the media path and request type to log records,
    and populates them using the matching ContextVars;
    """
    old_factory = logging.getLogRecordFactory()

    def _factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = old_factory(*args, **kwargs)
        # Define custom attributes on the records. We need to ignore the types here
        # because otherwise mypy complains the attributes aren't defined on LogRecord.
        record.media_path = media_path.get(None)  # type: ignore[attr-defined]
        record.request_type = request_type.get(None)  # type: ignore[attr-defined]
        return record

    logging.setLogRecordFactory(_factory)


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
