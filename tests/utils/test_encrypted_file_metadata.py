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
import copy
import unittest

from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.encrypted_file_metadata import (
    validate_encrypted_file_metadata,
)
from matrix_content_scanner.utils.errors import ContentScannerRestError
from tests.testutils import ENCRYPTED_FILE_METADATA


class EncryptedMetadataValidationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = copy.deepcopy(ENCRYPTED_FILE_METADATA)

    def test_validate(self) -> None:
        """Tests that valid file metadata is considered as such."""
        validate_encrypted_file_metadata(ENCRYPTED_FILE_METADATA)

    def test_key_ops_no_decrypt(self) -> None:
        """Tests that the metadata validation fails if key_ops doesn't include `decrypt`."""
        self.metadata["file"]["key"]["key_ops"] = ["encrypt"]
        self._test_fails_validation()

    def test_key_ops_no_encrypt(self) -> None:
        """Tests that the metadata validation fails if key_ops doesn't include `encrypt`."""
        self.metadata["file"]["key"]["key_ops"] = ["decrypt"]
        self._test_fails_validation()

    def test_ops_extra_values(self) -> None:
        """tests that the metadata validation does not fail if there are extra values in
        key_ops.
        """
        self.metadata["file"]["key"]["key_ops"].append("foo")
        validate_encrypted_file_metadata(self.metadata)

    def test_no_file(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file` property."""
        self.metadata = {"foo": "bar"}
        self._test_fails_validation()

    def test_no_key(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file.key` property."""
        del self.metadata["file"]["key"]
        self._test_fails_validation()

    def test_no_k(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file.key.k`
        property.
        """
        del self.metadata["file"]["key"]["k"]
        self._test_fails_validation()

    def test_no_ext(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file.key.ext`
        property.
        """
        del self.metadata["file"]["key"]["ext"]
        self._test_fails_validation()

    def test_bad_ext(self) -> None:
        """Tests that the metadata validation fails if the `file.key.ext` property has an
        invalid value.
        """
        self.metadata["file"]["key"]["ext"] = False
        self._test_fails_validation()

    def test_bad_alg(self) -> None:
        """Tests that the metadata validation fails if the `file.key.alg` property has an
        invalid value.
        """
        self.metadata["file"]["key"]["alg"] = "bad"
        self._test_fails_validation()

    def test_bad_kty(self) -> None:
        """Tests that the metadata validation fails if the `file.key.kty` property has an
        invalid value.
        """
        self.metadata["file"]["key"]["kty"] = "bad"
        self._test_fails_validation()

    def test_no_iv(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file.iv` property."""
        del self.metadata["file"]["iv"]
        self._test_fails_validation()

    def test_no_url(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file.url` property."""
        del self.metadata["file"]["url"]
        self._test_fails_validation()

    def test_no_hashes(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file.hashes`
        property.
        """
        del self.metadata["file"]["hashes"]
        self._test_fails_validation()

    def test_no_sha256(self) -> None:
        """Tests that the metadata validation fails if there isn't a `file.hashes.sha256`
        property.
        """
        del self.metadata["file"]["hashes"]["sha256"]
        self._test_fails_validation()

    def _test_fails_validation(self) -> None:
        """Tests that the validation fails with a REST error complaining about malformed
        JSON.
        """
        with self.assertRaises(ContentScannerRestError) as cm:
            validate_encrypted_file_metadata(self.metadata)

        self.assertEqual(cm.exception.http_status, 400)
        self.assertEqual(cm.exception.reason, ErrCode.MALFORMED_JSON)
