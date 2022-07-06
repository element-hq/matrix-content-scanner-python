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
from matrix_content_scanner.utils.constants import ErrCode


class ContentScannerRestError(Exception):
    """An error that is converted into an error response by the REST resource."""

    def __init__(self, http_status: int, reason: ErrCode, info: str) -> None:
        super(Exception, self).__init__(info)
        self.http_status = http_status
        self.reason = reason
        self.info = info


class FileDirtyError(ContentScannerRestError):
    """An error indicating that the file being scanned is dirty."""

    def __init__(self, info: str = "***VIRUS DETECTED***") -> None:
        super(FileDirtyError, self).__init__(
            http_status=403,
            reason=ErrCode.NOT_CLEAN,
            info=info,
        )


class ConfigError(Exception):
    """An error indicating an issue with the configuration file."""

    pass


class WellKnownDiscoveryError(Exception):
    """An error indicating a failure when attempting a .well-known discovery."""

    pass
