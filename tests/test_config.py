# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
import unittest
from tempfile import NamedTemporaryFile

from tests.testutils import get_content_scanner


class ConfigTestCase(unittest.TestCase):
    def test_request_secret_file_missing(self) -> None:
        mcs = get_content_scanner(
            {
                "crypto": {
                    "request_secret_path": "nonexisting",
                },
            },
        )

        self.assertRaises(
            FileNotFoundError,
            mcs.config.crypto.get_request_secret,
        )

    def test_request_secret_file_malformed(self) -> None:
        with NamedTemporaryFile() as pickle_key_file:
            pickle_key_file.write("🙈🙉🙊".encode())
            pickle_key_file.flush()

            mcs = get_content_scanner(
                {
                    "crypto": {
                        "request_secret_path": pickle_key_file.name,
                    },
                },
            )
            self.assertRaises(
                ValueError,
                mcs.config.crypto.get_request_secret,
            )

    def test_request_secret_file_too_short(self) -> None:
        with NamedTemporaryFile() as pickle_key_file:
            pickle_key_file.write(b"Rm9ybW8K")
            pickle_key_file.flush()

            mcs = get_content_scanner(
                {
                    "crypto": {
                        "request_secret_path": pickle_key_file.name,
                    },
                },
            )

            self.assertRaises(
                ValueError,
                mcs.config.crypto.get_request_secret,
            )

    def test_pickle_key_in_config(self) -> None:
        with NamedTemporaryFile() as pickle_key_file:
            pickle_key_file.write(b"8J+Mu/CfjLvwn4y78J+Mu/CfjLvwn4y78J+Mu/CfjLs=")
            pickle_key_file.flush()

            mcs = get_content_scanner(
                {
                    "crypto": {
                        "request_secret_path": pickle_key_file.name,
                    },
                },
            )
            self.assertEqual(
                mcs.config.crypto.get_request_secret(),
                "🌻🌻🌻🌻🌻🌻🌻🌻".encode(),
            )
