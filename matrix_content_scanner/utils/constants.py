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
from enum import Enum


class ErrCode(str, Enum):
    # An unknown error happened.
    UNKNOWN = "M_UNKNOWN"
    # No route was found with the path and method provided in the request.
    NOT_FOUND = "M_NOT_FOUND"
    # The file failed the scan.
    NOT_CLEAN = "MCS_MEDIA_NOT_CLEAN"
    # The file could not be retrieved from the homeserver.
    REQUEST_FAILED = "MCS_MEDIA_REQUEST_FAILED"
    # The encrypted file could not be decrypted with the provided metadata.
    FAILED_TO_DECRYPT = "MCS_MEDIA_FAILED_TO_DECRYPT"
    # The request body isn't valid JSON, or is missing a required parameter.
    MALFORMED_JSON = "MCS_MALFORMED_JSON"
