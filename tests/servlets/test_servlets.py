#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
import json
import unittest

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
        metadata = _metadata_from_body(ENCRYPTED_FILE_METADATA, self.crypto_handler)
        self.assertEqual(metadata, ENCRYPTED_FILE_METADATA)

    def test_encrypted(self) -> None:
        """Tests that the _metadata_from_body function correctly decrypts Olm-encrypted
        metadata and returns a decrypted version.
        """
        encrypted_body = self._encrypt_body(ENCRYPTED_FILE_METADATA)
        metadata = _metadata_from_body(encrypted_body, self.crypto_handler)
        self.assertEqual(metadata, ENCRYPTED_FILE_METADATA)

    def test_bad_json(self) -> None:
        """Tests that the _metadata_from_body function raises a REST error if the request
        body is not a valid JSON object.
        """
        with self.assertRaises(ContentScannerRestError) as cm:
            _metadata_from_body("foo", self.crypto_handler)  # type: ignore[arg-type]

        self.assertEqual(cm.exception.reason, ErrCode.MALFORMED_JSON)

    def _encrypt_body(self, content: JsonDict) -> JsonDict:
        """Encrypts the provided dictionary with Olm's PkEncryption class.

        Args:
            content: The dictionary to encrypt.

        Returns:
            An encrypted version of the dictionary in the format that's expected in POST
            requests.
        """
        msg = self.crypto_handler.encrypt(
            self.crypto_handler.public_key, json.dumps(content)
        )

        return {
            "encrypted_body": {
                "ciphertext": msg.ciphertext,
                "mac": msg.mac,
                "ephemeral": msg.ephemeral_key,
            }
        }
