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
from typing import Any, Callable, Dict, List, Optional, Union

import attr
import humanfriendly
from jsonschema import ValidationError, validate

from matrix_content_scanner.utils.errors import ConfigError

# Schema to validate the raw configuration dictionary against.
_config_schema = {
    "type": "object",
    "required": ["web", "scan", "crypto"],
    "additionalProperties": False,
    "properties": {
        "web": {
            "type": "object",
            "required": ["host", "port"],
            "additionalProperties": False,
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "number"},
            },
        },
        "scan": {
            "type": "object",
            "required": ["script", "temp_directory"],
            "additionalProperties": False,
            "properties": {
                "script": {"type": "string"},
                "temp_directory": {"type": "string"},
                "do_not_cache_exit_codes": {
                    "type": "array",
                    "items": {"type": "number"},
                },
                "removal_command": {"type": "string"},
                "allowed_mimetypes": {"type": "array", "items": {"type": "string"}},
            },
        },
        "download": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "base_homeserver_url": {"type": "string"},
                "proxy": {"type": "string"},
                "allowed_mimetypes": {"type": "object"},
            },
        },
        "crypto": {
            "type": "object",
            "required": ["pickle_path", "pickle_key"],
            "additionalProperties": False,
            "properties": {
                "pickle_path": {"type": "string"},
                "pickle_key": {"type": "string"},
            },
        },
    },
}


@attr.s(auto_attribs=True, frozen=True)
class WebConfig:
    """Configuration for serving the HTTP API."""

    host: str
    port: int


@attr.s(auto_attribs=True, frozen=True, slots=True)
class ScanConfig:
    """Configuration for scanning files."""

    script: str
    temp_directory: str
    removal_command: str = "rm"
    allowed_mimetypes: Optional[List[str]] = None


@attr.s(auto_attribs=True, frozen=True, slots=True)
class ResultCacheConfig:
    """Configuration for caching scan results."""

    max_size: int = 1024
    ttl: Union[str, float] = "1w"
    exit_codes_to_ignore: Optional[List[int]] = None
    max_file_size: Optional[Union[str, float]] = None


@attr.s(auto_attribs=True, frozen=True, slots=True)
class DownloadConfig:
    """Configuration for downloading files."""

    base_homeserver_url: Optional[str] = None
    proxy: Optional[str] = None
    additional_headers: Optional[Dict[str, str]] = None


@attr.s(auto_attribs=True, frozen=True, slots=True)
class CryptoConfig:
    """Configuration for decrypting encrypted bodies."""

    pickle_path: str
    pickle_key: str


class MatrixContentScannerConfig:
    def __init__(self, config_dict: Dict[str, Any]):
        if not isinstance(config_dict, dict):
            raise ConfigError("Bad configuration format")

        try:
            validate(config_dict, _config_schema)
        except ValidationError as e:
            raise ConfigError(e.message)

        self.web = WebConfig(**(config_dict.get("web") or {}))
        self.scan = ScanConfig(**(config_dict.get("scan") or {}))
        self.crypto = CryptoConfig(**(config_dict.get("crypto") or {}))
        self.download = DownloadConfig(**(config_dict.get("download") or {}))
        self.result_cache = ResultCacheConfig(**(config_dict.get("result_cache") or {}))


def parse_duration(duration: Optional[Union[str, float]]) -> Optional[float]:
    """Parse a time duration into a float representing an amount of second. If the given
    value is None, or already a float, returns it as is.

    Args:
        duration: The duration to parse.

    Returns:
        The number of seconds in the given duration.
    """
    return _parse_user_value(duration, humanfriendly.parse_timespan)


def parse_size(size: Optional[Union[str, float]]) -> Optional[float]:
    """Parse a file size into a float representing the number of bytes for that size. If
    the given value is None, or already a float, returns it as is.

    Args:
        size: The size to parse.

    Returns:
        The number of bytes represented by the given size.
    """
    return _parse_user_value(size, humanfriendly.parse_size)


def _parse_user_value(
    v: Optional[Union[str, float]], parser: Callable[[str], float]
) -> Optional[float]:
    """Parse a given user-defined string value (such as durations or sizes) into a float.

    If the value is None or is already a float, or is None, returns it directly.
    Otherwise, use the provided parsing function.

    Args:
        v: The value to parse.
        parser: The function to use to parse string values.

    Returns:
        The provided value if it's None or a float, otherwise the return value of the
        parsing function.
    """
    if v is None:
        return None

    if isinstance(v, float):
        return v

    return parser(v)
