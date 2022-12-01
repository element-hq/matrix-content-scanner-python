# Copyright 2022 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import logging
import sys
from functools import cached_property

import yaml
from yaml.scanner import ScannerError

from matrix_content_scanner import logutils
from matrix_content_scanner.config import MatrixContentScannerConfig
from matrix_content_scanner.crypto import CryptoHandler
from matrix_content_scanner.httpserver import HTTPServer
from matrix_content_scanner.scanner.file_downloader import FileDownloader
from matrix_content_scanner.scanner.scanner import Scanner
from matrix_content_scanner.utils.errors import ConfigError

logger = logging.getLogger(__name__)


class MatrixContentScanner:
    def __init__(
        self,
        config: MatrixContentScannerConfig,
    ) -> None:
        self.config = config

    @cached_property
    def file_downloader(self) -> FileDownloader:
        return FileDownloader(self)

    @cached_property
    def scanner(self) -> Scanner:
        return Scanner(self)

    @cached_property
    def crypto_handler(self) -> CryptoHandler:
        return CryptoHandler(self)

    def start(self) -> None:
        setup_logging()
        http_server = HTTPServer(self)
        http_server.start()


def setup_logging() -> None:
    """Basic logging setup."""
    # Set the format, this assumes every logger is created by
    # matrix_content_scanner.logging.getLogger and has custom request_type and
    # media_path fields set.
    log_format = "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request_id)s - %(message)s"
    formatter = logging.Formatter(log_format)

    logutils.setup_custom_factory()

    # Create the handler and set the default logging level to INFO.
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    rootLogger = logging.getLogger("")
    rootLogger.setLevel(logging.INFO)
    rootLogger.addHandler(handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A web service for scanning media hosted by a Matrix media repository."
    )
    parser.add_argument(
        "-c",
        type=argparse.FileType("r"),
        required=True,
        help="The YAML configuration file.",
    )

    args = parser.parse_args()

    # Load the configuration file.
    try:
        cfg = MatrixContentScannerConfig(yaml.safe_load(args.c))
    except (ConfigError, ScannerError) as e:
        # If there's an error reading the file, print it and exit without raising so we
        # don't confuse/annoy the user with an unnecessary stack trace.
        print("Failed to read configuration file: %s" % e, file=sys.stderr)
        sys.exit(1)

    # Create the content scanner.
    mcs = MatrixContentScanner(cfg)

    # Construct the crypto handler early on, so we can make sure we can load the Olm key
    # pair from the pickle file (or write it if it doesn't already exist).
    try:
        _ = mcs.crypto_handler
    except ConfigError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    # Start the content scanner.
    mcs.start()
