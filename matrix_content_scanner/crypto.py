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
import logging
from typing import TYPE_CHECKING

from olm.pk import PkDecryption, PkDecryptionError, PkMessage

from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError
from matrix_content_scanner.utils.types import JsonDict

if TYPE_CHECKING:
    from matrix_content_scanner.mcs import MatrixContentScanner


logger = logging.getLogger(__name__)


class CryptoHandler:
    """Handler for handling Olm-encrypted request bodies."""

    def __init__(self, mcs: "MatrixContentScanner") -> None:
        key = mcs.config.crypto.pickle_key
        path = mcs.config.crypto.pickle_path
        try:
            # Try reading the pickle from disk.
            with open(path, "r") as fp:
                pickle = fp.read()

            # Create a PkDecryption object with the content and key.
            self._decryptor: PkDecryption = PkDecryption.from_pickle(
                pickle=pickle.encode("ascii"),
                passphrase=key,
            )

            logger.info("Loaded Olm pickle from %s", path)
        except FileNotFoundError:
            # If the pickle file doesn't exist, try creating it.
            self._decryptor = PkDecryption()
            pickle_bytes = self._decryptor.pickle(passphrase=key)

            logger.info(
                "Olm pickle not found, generating one and saving it at %s", path
            )

            with open(path, "w+") as fp:
                fp.write(pickle_bytes.decode("ascii"))

        self.public_key = self._decryptor.public_key

    def decrypt_body(self, ciphertext: str, mac: str, ephemeral: str) -> JsonDict:
        """Decrypts an Olm-encrypted body.

        Args:
            ciphertext: The encrypted body's ciphertext.
            mac: The encrypted body's MAC.
            ephemeral: The encrypted body's ephemeral key.

        Returns:
            The decrypted body, parsed as JSON.
        """
        try:
            decrypted = self._decryptor.decrypt(
                message=PkMessage(
                    ephemeral_key=ephemeral,
                    mac=mac,
                    ciphertext=ciphertext,
                )
            )
        except PkDecryptionError as e:
            logger.error("Failed to decrypt encrypted body: %s", e)
            raise ContentScannerRestError(
                http_status=400,
                reason=ErrCode.FAILED_TO_DECRYPT,
                info=str(e),
            )

        # We know that `decrypted` parses as a JsonDict.
        return json.loads(decrypted)  # type: ignore[no-any-return]
