#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only
# Please see LICENSE in the repository root for full details.
from enum import Enum


class ErrCode(str, Enum):
    # An unknown error happened.
    UNKNOWN = "M_UNKNOWN"
    # One of the following:
    # - No route was found with the path and method provided in the request.
    # - The homeserver does not have the requested piece of media.
    NOT_FOUND = "M_NOT_FOUND"
    # The file failed the scan.
    NOT_CLEAN = "MCS_MEDIA_NOT_CLEAN"
    # The file could not be retrieved from the homeserver.
    # Does NOT cover homeserver responses with M_NOT_FOUND.
    REQUEST_FAILED = "MCS_MEDIA_REQUEST_FAILED"
    # The encrypted file could not be decrypted with the provided metadata.
    FAILED_TO_DECRYPT = "MCS_MEDIA_FAILED_TO_DECRYPT"
    # The request body isn't valid JSON, or is missing a required parameter.
    MALFORMED_JSON = "MCS_MALFORMED_JSON"
    # The Mime type is not in the allowed list of Mime types.
    MIME_TYPE_FORBIDDEN = "MCS_MIME_TYPE_FORBIDDEN"
