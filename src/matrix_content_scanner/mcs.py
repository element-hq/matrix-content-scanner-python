# Copyright 2022 New Vector Ltd
#
# SPDX-License-Identifier: AGPL-3.0-only
# Please see LICENSE in the repository root for full details.
import argparse
import logging
import sys
from functools import cached_property

import yaml
from yaml.scanner import ScannerError

from matrix_content_scanner import logutils
from matrix_content_scanner.config import MatrixContentScannerConfig
from matrix_content_scanner.httpserver import HTTPServer
from matrix_content_scanner.mcs_rust import crypto, reset_logging_config
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
    def crypto_handler(self) -> crypto.CryptoHandler:
        return crypto.CryptoHandler(
            self.config.crypto.pickle_key, self.config.crypto.pickle_path
        )

    def start(self) -> None:
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

    reset_logging_config()


def main() -> None:
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

    setup_logging()

    # Construct the crypto handler early on, so we can make sure we can load the Olm key
    # pair from the pickle file (or write it if it doesn't already exist).
    try:
        _ = mcs.crypto_handler
    except ConfigError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    # Start the content scanner.
    mcs.start()


if __name__ == "__main__":
    main()
