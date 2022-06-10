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
from typing import Any, Dict, List, Optional

import attr
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
    do_not_cache_exit_codes: Optional[List[int]] = None
    removal_command: str = "rm"
    allowed_mimetypes: Optional[List[str]] = None


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
