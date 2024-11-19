#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only
# Please see LICENSE in the repository root for full details.
import json
import unittest

from tests.testutils import get_content_scanner


class CryptoHandlerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.crypto_handler = get_content_scanner().crypto_handler

    def test_decrypt(self) -> None:
        """Tests that an Olm-encrypted payload is successfully decrypted."""
        payload = {"foo": "bar"}

        # Encrypt the payload with PkEncryption.
        encrypted = self.crypto_handler.encrypt(
            self.crypto_handler.public_key, json.dumps(payload)
        )

        # Decrypt the payload with the crypto handler.
        decrypted = json.loads(
            get_content_scanner().crypto_handler.decrypt_body(
                encrypted.ciphertext,
                encrypted.mac,
                encrypted.ephemeral_key,
            )
        )

        # Check that the decrypted payload is the same as the original one before
        # encryption.
        self.assertEqual(decrypted, payload)
