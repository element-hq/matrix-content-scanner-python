# Copyright 2022 The Matrix.org Foundation C.I.C.
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

import twisted.internet.reactor
import yaml
from twisted.internet.interfaces import IReactorCore, IReactorTCP
from twisted.python import log
from yaml.scanner import ScannerError

from matrix_content_scanner import logutils
from matrix_content_scanner.config import MatrixContentScannerConfig
from matrix_content_scanner.crypto import CryptoHandler
from matrix_content_scanner.httpserver import HTTPServer
from matrix_content_scanner.scanner.file_downloader import FileDownloader
from matrix_content_scanner.scanner.scanner import Scanner
from matrix_content_scanner.utils.errors import ConfigError

logger = logging.getLogger(__name__)


class Reactor(
    IReactorCore,
    IReactorTCP,
):
    """A dummy class we use to tell mypy the reactor we're using has the methods we need."""

    pass


class MatrixContentScanner:
    def __init__(
        self,
        config: MatrixContentScannerConfig,
        reactor: Reactor = twisted.internet.reactor,  # type: ignore[assignment]
    ) -> None:
        self.config = config
        self.reactor = reactor

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
        """Start the HTTP server and start the reactor."""
        setup_logging()
        http_server = HTTPServer(self)
        http_server.start()
        self.reactor.run()


def setup_logging() -> None:
    """Basic logging setup."""
    # Set the format, this assumes every logger is created by
    # matrix_content_scanner.logging.getLogger and has custom request_type and
    # media_path fields set.
    log_format = "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request_type)s - %(media_path)s - %(message)s"
    formatter = logging.Formatter(log_format)

    logutils.setup_custom_factory()

    # Create the handler and set the default logging level to INFO.
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    rootLogger = logging.getLogger("")
    rootLogger.setLevel(logging.INFO)
    rootLogger.addHandler(handler)

    observer = log.PythonLoggingObserver()
    observer.start()


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
        logger.error("Failed to read configuration file: %s", e)
        sys.exit(1)

    # Start the content scanner.
    mcs = MatrixContentScanner(cfg)
    mcs.start()
