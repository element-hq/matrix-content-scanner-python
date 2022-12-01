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
import os
from binascii import unhexlify
from typing import Dict, Optional

from multidict import CIMultiDict, CIMultiDictProxy, MultiDict, MultiDictProxy

from matrix_content_scanner.config import MatrixContentScannerConfig
from matrix_content_scanner.mcs import MatrixContentScanner
from matrix_content_scanner.utils.types import JsonDict

# The media path to use in tests.
MEDIA_PATH = "foo/bar"

# A small, unencrypted PNG.
SMALL_PNG = unhexlify(
    b"89504e470d0a1a0a0000000d4948445200000001000000010806"
    b"0000001f15c4890000000a49444154789c63000100000500010d"
    b"0a2db40000000049454e44ae426082"
)

# A small, encrypted PNG.
SMALL_PNG_ENCRYPTED = unhexlify(
    b"9fd28dd7a1d845a04948f13af104e39402c888f7b601bce313ad"
    b"bf3e2423f67d93d5e304efc147d46df511abacbb8ae7e2e8156c"
    b"2e08de86c31fdc6aa5bd4d11537e5657102a83214d13d7ff57e6"
    b"d35940f149fbd1e661a260b0b6fe465e4e0a7c8039c08d78f679"
    b"cde511be94c685eee50571858d99d0c84918381aea3e52319509"
    b"36cac1a7b2ec46c980f3c3995eaf21fc2711b0de8ff014ff5fe7"
    b"4a7fcb3515df4f1f2ceeae72d7b58bc69d56dedf31fd430ac2ce"
    b"8aee9fcb150a1af9fdee30ac26d68d3db77c1adec5f68cad78f9"
    b"ed6ef9156ba23b76e38dfd59cb077c964248f331d43147dc7fa7"
    b"b61baf7546e5edfd78347828386b64b3a1ebdff0dcd55ea57f4b"
    b"b73b06fbedff62ef8a7fd89146fd11723e739d541d07bf399837"
    b"3ed56cb9ef475bd409e590258cdb6a0cdf4871882c334c2897c4"
    b"ea0dc76748e727a71d8c2e85253b2c80667f5d98ddbcf8fb90ba"
    b"adceb6e75a2741b740dc0d084d55cc20dd7369e7041529b62ce1"
    b"59bcde9d9a0f4978093cd52dfe77107613d2bc265519177ed623"
    b"49d70517ecf4a243fb7c20db411459766785ee6f039f68383a62"
    b"375b14cdf405401dc4aabf6812d9803218544d1ccdc9339e81cb"
    b"b36acb3414e8dfb49521b89f1b6d54a712da35e45462844a622c"
    b"aa92313335d317201e1eab5f34daba5358fde87648b24868b098"
    b"505916b8bc997b19976487718835f0d54a8794e24ca19240cad1"
    b"61e0624d8df2214edd3c33ae2b5156e2ef7191d75528f9c26a89"
    b"4a"
)

# The metadata necessary to download and decrypt SMALL_PNG_ENCRYPTED
ENCRYPTED_FILE_METADATA: JsonDict = {
    "file": {
        "v": "v2",
        "key": {
            "alg": "A256CTR",
            "ext": True,
            "k": "F3miZm2vZhucJ062AuKMUwmd-O6AK0AXP29p4MKtq3Q",
            "key_ops": ["encrypt", "decrypt"],
            "kty": "oct",
        },
        "iv": "rJqtSdi3F/EAAAAAAAAAAA",
        "hashes": {"sha256": "NYvGRRQGfyWpXSUpba+ozSbehFP6kw5ZDg0xMppyX8c"},
        "url": "mxc://" + MEDIA_PATH,
    }
}


def to_thumbnail_params(params: Dict[str, str]) -> MultiDictProxy[str]:
    """Turn the given dictionary into query parameters as they'd appear when processing a
    thumbnailing request.

    Args:
        params: The raw parameters.

    Returns:
        A multidict that can be passed onto the scanner or the file downloader.
    """
    return MultiDictProxy(MultiDict(params))


def get_base_media_headers() -> CIMultiDictProxy[str]:
    """Get the base headers necessary to react to a download request for SMALL_PNG.

    Returns:
        The headers to pass onto the file downloader.
    """
    return CIMultiDictProxy(CIMultiDict({"content-type": "image/png"}))


def get_content_scanner(config: Optional[JsonDict] = None) -> MatrixContentScanner:
    """Instantiates an instance of the content scanner.

    Args:
        config: The optional provided config.
    """
    # Create the temporary directory that we'll use so the scanner doesn't complain about
    # it not existing.
    os.makedirs(os.path.abspath("temp"), exist_ok=True)

    # We define the default configuration here rather than as a constant outside of a
    # function because otherwise a test that sets its own config would have side effects
    # on the config used for other tests.
    default_config = {
        "scan": {
            "script": "true",
            "temp_directory": "temp",
        },
        "web": {
            "host": "127.0.0.1",
            "port": 8080,
        },
        "crypto": {
            "pickle_path": "mcs_pickle.txt",
            "pickle_key": "foo",
        },
    }

    if config is None:
        config = {}

    # Update the configuration provided with some default settings.
    # Note that `update` does not update nested dictionaries (only the top level), so
    # e.g. if a configuration with a `scan` section is provided it will need to include
    # all required settings in that section.
    default_config.update(config)

    parsed_config = MatrixContentScannerConfig(default_config)

    return MatrixContentScanner(parsed_config)
