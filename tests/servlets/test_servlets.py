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
import json
import unittest

from olm.pk import PkEncryption

from matrix_content_scanner.servlets import _metadata_from_body
from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict
from tests.testutils import ENCRYPTED_FILE_METADATA, get_content_scanner


class EncryptedFileMetadataTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.crypto_handler = get_content_scanner().crypto_handler

    def test_unencrypted(self) -> None:
        """Tests that the _metadata_from_body function correctly returns non-encrypted
        metadata.
        """
        body_bytes = json.dumps(ENCRYPTED_FILE_METADATA)
        metadata = _metadata_from_body(body_bytes, self.crypto_handler)
        self.assertEqual(metadata, ENCRYPTED_FILE_METADATA)

    def test_encrypted(self) -> None:
        """Tests that the _metadata_from_body function correctly decrypts Olm-encrypted
        metadata and returns a decrypted version.
        """
        encrypted_body = self._encrypt_body(ENCRYPTED_FILE_METADATA)
        body_bytes = json.dumps(encrypted_body)
        metadata = _metadata_from_body(body_bytes, self.crypto_handler)
        self.assertEqual(metadata, ENCRYPTED_FILE_METADATA)

    def test_bad_json(self) -> None:
        """Tests that the _metadata_from_body function raises a REST error if the request
        body is not valid JSON.
        """
        with self.assertRaises(ContentScannerRestError) as cm:
            _metadata_from_body("foo", self.crypto_handler)

        self.assertEqual(cm.exception.reason, ErrCode.MALFORMED_JSON)

    def _encrypt_body(self, content: JsonDict) -> JsonDict:
        """Encrypts the provided dictionary with Olm's PkEncryption class.

        Args:
            content: The dictionary to encrypt.

        Returns:
            An encrypted version of the dictionary in the format that's expected in POST
            requests.
        """
        pke = PkEncryption(self.crypto_handler.public_key)
        plaintext = json.dumps(content)
        msg = pke.encrypt(plaintext)

        return {
            "encrypted_body": {
                "ciphertext": msg.ciphertext,
                "mac": msg.mac,
                "ephemeral": msg.ephemeral_key,
            }
        }
