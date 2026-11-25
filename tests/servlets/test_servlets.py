#  Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
import copy
import json
import unittest
from unittest.mock import AsyncMock, Mock

from matrix_content_scanner.servlets import (
    _metadata_from_body,
    get_media_metadata_from_request,
    get_mxc_uri_from_request,
)
from matrix_content_scanner.utils.constants import ErrCode
from matrix_content_scanner.utils.errors import ContentScannerRestError, FileDirtyError
from matrix_content_scanner.utils.types import JsonDict

from tests.testutils import (
    ENCRYPTED_FILE_METADATA,
    MEDIA_PATH,
    MXC_URI,
    get_content_scanner,
)


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


class MediaMetadataFromRequestTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.crypto_handler = get_content_scanner().crypto_handler

    async def test_mxc_uri(self) -> None:
        """Tests that get_media_metadata_from_request correctly parses the MXC URI in the
        request body.
        """
        mxc_uri, metadata = await get_media_metadata_from_request(
            self._make_request(ENCRYPTED_FILE_METADATA), self.crypto_handler
        )
        self.assertEqual(mxc_uri, MXC_URI)
        self.assertEqual(metadata, ENCRYPTED_FILE_METADATA)

    async def test_invalid_mxc_uri(self) -> None:
        """Tests that get_media_metadata_from_request raises a REST error if the file's
        URL isn't a valid MXC URI.
        """
        for url in [
            "https://" + MEDIA_PATH,
            "mxc://" + MEDIA_PATH + "/baz",
            "mxc://" + MEDIA_PATH + "?foo=bar",
            "mxc://foo",
            "mxc:///bar",
        ]:
            with self.subTest(url=url):
                body = copy.deepcopy(ENCRYPTED_FILE_METADATA)
                body["file"]["url"] = url

                with self.assertRaises(ContentScannerRestError) as cm:
                    await get_media_metadata_from_request(
                        self._make_request(body), self.crypto_handler
                    )

                self.assertEqual(cm.exception.http_status, 400)
                self.assertEqual(cm.exception.reason, ErrCode.MALFORMED_JSON)

    def _make_request(self, body: JsonDict) -> Mock:
        """Builds a mock request with the given JSON body."""
        request = Mock()
        request.json = AsyncMock(return_value=body)
        return request


class MXCUriFromRequestTestCase(unittest.TestCase):
    def test_valid_media_path(self) -> None:
        """Tests that get_mxc_uri_from_request turns a valid media path into an MXC URI."""
        self.assertEqual(
            get_mxc_uri_from_request(self._make_request(MEDIA_PATH)), MXC_URI
        )

    def test_invalid_media_path(self) -> None:
        """Tests that get_mxc_uri_from_request raises a FileDirtyError if the media path
        doesn't form a valid MXC URI.
        """
        for media_path in [
            MEDIA_PATH + "/baz",
            MEDIA_PATH + "?foo=bar",
            MEDIA_PATH + "#foo",
            "foo",
            "foo/",
            "/bar",
        ]:
            with self.subTest(media_path=media_path):
                with self.assertRaises(FileDirtyError) as cm:
                    get_mxc_uri_from_request(self._make_request(media_path))

                self.assertEqual(cm.exception.info, "Malformed media ID")

    def _make_request(self, media_path: str) -> Mock:
        """Builds a mock request with the given media path in its URL."""
        request = Mock()
        request.match_info = {"media_path": media_path}
        return request
