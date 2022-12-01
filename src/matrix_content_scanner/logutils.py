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
import logging
from contextvars import ContextVar
from typing import Any

# The request's ID.
request_id: ContextVar[str] = ContextVar("request_id")


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
        record.request_id = request_id.get(None)  # type: ignore[attr-defined]
        return record

    logging.setLogRecordFactory(_factory)


def set_request_id_in_context(v: str) -> None:
    """Sets the request_id ContextVar to the given value.

    Args:
        v: The value to set the ContextVar.
    """
    request_id.set(v)
