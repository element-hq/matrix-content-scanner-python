#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only
# Please see LICENSE in the repository root for full details.
from typing import Any, Dict

import attr
from multidict import CIMultiDictProxy


@attr.s(auto_attribs=True)
class MediaDescription:
    """A description of a media."""

    content_type: str
    content: bytes
    response_headers: CIMultiDictProxy[str]
    cacheable: bool = True


# A JSON object/dictionary.
JsonDict = Dict[str, Any]
