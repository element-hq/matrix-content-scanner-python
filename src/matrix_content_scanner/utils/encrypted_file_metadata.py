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
from jsonschema import ValidationError, validate

from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict

# This is a subset of the content of an m.room.message event that includes a file, with
# only the info that we need to locate and decrypt the file.
_encrypted_file_metadata_schema = {
    "type": "object",
    "required": ["file"],
    "properties": {
        "file": {
            "type": "object",
            "required": ["v", "iv", "url", "hashes", "key"],
            "properties": {
                "v": {"const": "v2"},
                "iv": {"type": "string"},
                "url": {"type": "string"},
                "hashes": {
                    "type": "object",
                    "required": ["sha256"],
                    "properties": {
                        "sha256": {"type": "string"},
                    },
                },
                "key": {
                    "type": "object",
                    "required": ["alg", "kty", "k", "key_ops", "ext"],
                    "properties": {
                        "alg": {"const": "A256CTR"},
                        "kty": {"const": "oct"},
                        "k": {"type": "string"},
                        "key_ops": {"type": "array", "items": {"type": "string"}},
                        "ext": {"const": True},
                    },
                },
            },
        },
    },
}


def _validate(body: JsonDict) -> None:
    """Validates the schema using jsonschema, and by checking whether the `key_ops` list
    includes at least `encrypt` and `decrypt`.

    Args:
        body: The body to validate.

    Raises:
        ValidationError if the jsonschema validation failed.
        ValueError if the `key_ops` list doesn't include at least `encrypt` and `decrypt`.
    """
    validate(body, _encrypted_file_metadata_schema)

    # We don't need to worry about triggering a KeyError/TypeError here because all of
    # these keys are marked as required in the schema, so at this point we know they're
    # here.
    key_ops = body["file"]["key"]["key_ops"]
    # We need the key_ops list to at least include "encrypt" and "decrypt", but we can't
    # check this with jsonschema, so we need to do it manually.
    if not set(key_ops).issuperset({"encrypt", "decrypt"}):
        raise ValueError('key_ops must contain at least "encrypt" and "decrypt"')


def validate_encrypted_file_metadata(body: JsonDict) -> None:
    """Validates the schema of the given dictionary, and turns any validation error
    raised into a client error.

    Args:
        body: The body to validate.

    Raises:
        ContentScannerRestError(400) if the validation failed.
    """
    # Run the validation and turns any error coming out of it into a REST error.
    try:
        _validate(body)
    except ValidationError as e:
        raise ContentScannerRestError(400, ErrCode.MALFORMED_JSON, e.message)
    except ValueError as e:
        raise ContentScannerRestError(400, ErrCode.MALFORMED_JSON, str(e))
