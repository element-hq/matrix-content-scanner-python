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
import json
import unittest

from olm.pk import PkEncryption

from tests.testutils import get_content_scanner


class CryptoHandlerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.crypto_handler = get_content_scanner().crypto_handler

    def test_decrypt(self) -> None:
        """Tests that an Olm-encrypted payload is successfully decrypted."""
        payload = {"foo": "bar"}

        # Encrypt the payload with PkEncryption.
        pke = PkEncryption(self.crypto_handler.public_key)
        encrypted = pke.encrypt(json.dumps(payload))

        # Decrypt the payload with the crypto handler.
        decrypted = self.crypto_handler.decrypt_body(
            encrypted.ciphertext,
            encrypted.mac,
            encrypted.ephemeral_key,
        )

        # Check that the decrypted payload is the same as the original one before
        # encryption.
        self.assertEqual(decrypted, payload)
