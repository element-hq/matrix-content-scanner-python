#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
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
        record.request_id = request_id.get(None)
        return record

    logging.setLogRecordFactory(_factory)


def set_request_id_in_context(v: str) -> None:
    """Sets the request_id ContextVar to the given value.

    Args:
        v: The value to set the ContextVar.
    """
    request_id.set(v)
