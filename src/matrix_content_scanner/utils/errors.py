#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only
# Please see LICENSE in the repository root for full details.
from typing import Optional

from matrix_content_scanner.utils.constants import ErrCode


class ContentScannerRestError(Exception):
    """An error that is converted into an error response by the REST resource."""

    def __init__(self, http_status: int, reason: ErrCode, info: Optional[str]) -> None:
        super(Exception, self).__init__(info)
        self.http_status = http_status
        self.reason = reason
        self.info = info


class FileDirtyError(ContentScannerRestError):
    """An error indicating that the file being scanned is dirty."""

    def __init__(
        self,
        info: Optional[str] = "***VIRUS DETECTED***",
        cacheable: bool = True,
    ) -> None:
        """
        Args:
            info: The info string to serve to the client.
            cacheable: Whether raising this error should be recorded as a scan failure in
                the scanner's result cache.
        """
        super(FileDirtyError, self).__init__(
            http_status=403,
            reason=ErrCode.NOT_CLEAN,
            info=info,
        )

        self.cacheable = cacheable


class FileMimeTypeForbiddenError(ContentScannerRestError):
    """An error indicating that the file's MIME type is forbidden."""

    def __init__(self, info: Optional[str]) -> None:
        super(FileMimeTypeForbiddenError, self).__init__(
            http_status=403,
            reason=ErrCode.MIME_TYPE_FORBIDDEN,
            info=info,
        )


class ConfigError(Exception):
    """An error indicating an issue with the configuration file."""


class WellKnownDiscoveryError(Exception):
    """An error indicating a failure when attempting a .well-known discovery."""
