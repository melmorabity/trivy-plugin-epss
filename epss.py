#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2025 Mohamed El Morabity
# SPDX-License-Identifier: GPL-3.0-or-later

"""A Trivy plugin that enhances vulnerability scan results with EPSS data."""

from __future__ import annotations

import base64
import csv
import errno
import json
import logging
import os
import re
import shutil
import sys
import time
import typing
import urllib.parse
import urllib.request
from argparse import (
    ArgumentDefaultsHelpFormatter,
    ArgumentParser,
    ArgumentTypeError,
)
from datetime import datetime
from gzip import BadGzipFile, GzipFile
from http.client import HTTPException
from json import JSONDecodeError
from logging import Formatter, StreamHandler
from pathlib import Path
from tempfile import mkstemp
from typing import Any, ClassVar
from urllib.error import URLError
from urllib.request import Request

if typing.TYPE_CHECKING:  # pragma: nocover
    from logging import LogRecord


DEFAULT_EPSS_DATA_URL = (
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)
DEFAULT_EPSS_CACHE_DIR = Path.home() / ".cache" / "trivy" / "epss"
EPSS_FILENAME = "epss.csv"
DEFAULT_EPSS_DOWNLOAD_TIMEOUT = 60


class ISO8601Formatter(Formatter):
    """Custom log formatter that formats timestamps in ISO 8601 format."""

    LEVEL_COLORS: ClassVar[dict[str, str]] = {
        "INFO": "\033[34m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "FATAL": "\033[31m",
    }

    def formatTime(  # ruff: ignore[invalid-function-name, no-self-use]
        self,
        record: LogRecord,
        datefmt: str | None = None,  # ruff: ignore[unused-method-argument]
    ) -> str:
        """Format the timestamp of a log record using ISO 8601.

        Args:
            record (LogRecord): The log record whose timestamp to format.
            datefmt (str | None): Ignored. Present to match the signature of
                the base method.

        Returns:
            str: The formatted timestamp in ISO 8601 format.
        """
        return (
            datetime
            .fromtimestamp(record.created)
            .astimezone()
            .isoformat(timespec="seconds")
        )

    def format(self, record: LogRecord) -> str:
        """Format a log record, adding color to the log level name.

        Args:
            record (LogRecord): The log record to format.

        Returns:
            str: The formatted log record.
        """
        color = self.LEVEL_COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}\033[0m"
        return super().format(record)


handler = StreamHandler()
handler.setFormatter(
    ISO8601Formatter(fmt="%(asctime)s\t%(levelname)s\t[epss] %(message)s")
)
logging.getLogger().handlers = [handler]
logging.getLogger().setLevel(logging.INFO)


class TrivyPluginEPSSError(Exception):
    """Base class for exceptions raised by the Trivy EPSS plugin."""


def _build_epss_data_request(epss_data_url: str) -> Request:
    # urllib.request doesn't strip user credentials embedded in a URL (as in
    # https://user:pwd@server/...) before resolving the host, which makes
    # the connection fail. Extract them, if any, and turn them into an
    # Authorization header instead.
    url = urllib.parse.urlsplit(epss_data_url)
    if url.username is None:
        return Request(epss_data_url)  # ruff: ignore[suspicious-url-open-usage]

    # Credentials may be percent-encoded to include reserved characters
    # (e.g. ":" or "@"), so they must be unquoted before use.
    username = urllib.parse.unquote(url.username)
    password = urllib.parse.unquote(url.password) if url.password else ""
    authorization = base64.b64encode(f"{username}:{password}".encode()).decode(
        "ascii"
    )

    netloc = url.netloc.rpartition("@")[2]

    return Request(  # ruff: ignore[suspicious-url-open-usage]
        urllib.parse.urlunsplit(url._replace(netloc=netloc)),
        headers={"Authorization": f"Basic {authorization}"},
    )


def _download_epss_data(
    epss_data_url: str, target_file: Path, timeout: float
) -> None:
    # Write to a temporary file moved into place once complete, so that a
    # failed or concurrent update never exposes partial EPSS data
    request = _build_epss_data_request(epss_data_url)
    fd, temp_name = mkstemp(dir=target_file.parent)
    temp_path = Path(temp_name)
    try:
        with (
            os.fdopen(fd, "wb") as writer,
            urllib.request.urlopen(request, timeout=timeout) as response,  # ruff: ignore[suspicious-url-open-usage]
            GzipFile(fileobj=response) as gzip_file,
        ):
            shutil.copyfileobj(gzip_file, writer)
        temp_path.replace(target_file)
    finally:
        temp_path.unlink(missing_ok=True)


def update_epss_data(
    epss_data_url: str,
    target_file: Path,
    timeout: float = DEFAULT_EPSS_DOWNLOAD_TIMEOUT,
) -> None:
    """Download and update EPSS data if the cache is missing or outdated.

    Checks whether the target EPSS data file exists and is less than 24 hours
    old. If not, downloads the latest EPSS data from the given URL,
    decompresses it, and writes it to the target file.

    Args:
        epss_data_url (str): URL to download the (gzipped) EPSS data file,
            possibly with embedded user credentials (`https://user:pwd@server/...`).
        target_file (Path): Path where the EPSS data should be saved.
        timeout (float): Timeout in seconds for the EPSS data download.

    Raises:
        TrivyPluginEPSSError: If the data cannot be downloaded, decompressed,
        or saved.
    """
    # Check if file exists and its age
    if (
        target_file.is_file()
        and (time.time() - target_file.stat().st_mtime) < 24 * 60 * 60
    ):
        return

    target_file.parent.mkdir(exist_ok=True, parents=True)
    try:
        _download_epss_data(epss_data_url, target_file, timeout)
    except (URLError, TimeoutError, ConnectionError, HTTPException) as ex:
        raise TrivyPluginEPSSError(
            f"Failed to download EPSS data: {ex}"
        ) from None
    except BadGzipFile:
        raise TrivyPluginEPSSError("EPSS data are not gzipped") from None
    except EOFError:
        raise TrivyPluginEPSSError("EPSS data are truncated") from None
    except OSError as ex:
        raise TrivyPluginEPSSError(
            f"Unable to write EPSS data to {target_file}: {ex}"
        ) from None


def load_epss_data(csv_file: Path) -> dict[str, dict[str, Any]]:
    """Load EPSS data from a CSV file.

    Reads the EPSS CSV data, optionally extracts metadata from the first line,
    and returns a dictionary mapping CVE identifiers to their associated EPSS
    information.

    Args:
        csv_file (Path): Path to the EPSS CSV file.

    Returns:
        dict[str, dict[str, Any]]: Dictionary with CVE IDs as keys and a dict
            containing `score`, `percentile`, `model_version`, and `score_date`
            as values.

    Raises:
        TrivyPluginEPSSError: If the file cannot be read or is malformed.
    """
    data = {}
    model_version = None
    score_date = None

    try:
        content = csv_file.read_text(encoding="utf-8")
    except OSError as ex:
        raise TrivyPluginEPSSError(
            f"Unable to read EPSS data from {csv_file}: {ex}"
        ) from None
    except UnicodeError as ex:
        raise TrivyPluginEPSSError(f"Malformed EPSS data: {ex}") from None

    lines = content.splitlines()

    # Read metadata from the first line if present
    if lines and (
        match := re.match(
            r"\s*#\s*model_version\s*:\s*(.+?)\s*,"
            r"score_date\s*:\s*(.+?)\s*$",
            lines[0],
        )
    ):
        model_version, score_date = match.groups()
        lines = lines[1:]

    csv_lines = csv.reader(
        row
        for row in lines
        if re.match(
            r"\s*CVE-\d{4}-\d{4,}\s*,\s*\d+(\.\d+)?([eE][+-]?\d+)?\s*,"
            r"\s*\d+(\.\d+)?([eE][+-]?\d+)?\s*$",
            row,
        )
    )
    for fields in csv_lines:
        cve, score, percentile = fields
        data[cve] = {
            "score": float(score),
            "percentile": float(percentile),
            "model_version": model_version,
            "score_date": score_date,
        }

    return data


def dump_updated_results(
    epss_data: dict[str, dict[str, Any]], output_file: Path | None
) -> None:
    """Update Trivy scan results with EPSS data and write output.

    Reads Trivy scan results from standard input, injects EPSS data into
    vulnerabilities where possible, and writes the updated results to the given
    output file or standard output.

    Args:
        epss_data (dict[str, dict[str, Any]]): EPSS data indexed by CVE IDs.
        output_file (Path | None): Output file path, or `None` to write to
            stdout.

    Raises:
        TrivyPluginEPSSError: If input is not valid JSON, or if the output file
            cannot be written.
    """
    try:
        data = json.loads(sys.stdin.read())
    except JSONDecodeError:
        raise TrivyPluginEPSSError("Invalid JSON scan result") from None

    for result in data.get("Results") or []:
        for vulnerability in result.get("Vulnerabilities") or []:
            cve = vulnerability.get("VulnerabilityID")
            if cve and cve in epss_data:
                vulnerability.update({"EPSS": epss_data[cve]})

    if output_file:
        try:
            with output_file.open("w", encoding="UTF-8") as writer:
                json.dump(data, writer, indent=2)
        except OSError as ex:
            raise TrivyPluginEPSSError(
                f"Unable to write data to {output_file}: {ex}"
            ) from None
    else:
        try:
            json.dump(data, sys.stdout, indent=2)
        except OSError as ex:  # pragma: nocover
            # Ignore broken pipe errors that may occur when the output is piped
            # and the downstream process closes early
            if ex.errno != errno.EPIPE:
                raise TrivyPluginEPSSError(
                    f"Unable to write data to stdout: {ex}"
                ) from None


def _timeout_arg(value: str) -> float:
    timeout = float(value)
    # Also rejects NaN, for which all comparisons are false
    if not 0 < timeout < float("inf"):
        raise ArgumentTypeError(f"invalid timeout: {value}")

    return timeout


def _argument_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description="A Trivy plugin that enhances vulnerability scan results "
        "with EPSS data",
        formatter_class=ArgumentDefaultsHelpFormatter,
        prog="trivy epss",
    )
    parser.add_argument("-o", "--output", type=Path, help="output file name")
    parser.add_argument(
        "--epss-url",
        type=str,
        default=DEFAULT_EPSS_DATA_URL,
        help="EPSS data URL (must point to a Gzipped file)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_EPSS_CACHE_DIR,
        help="EPSS data cache directory",
    )
    parser.add_argument(
        "--timeout",
        type=_timeout_arg,
        default=DEFAULT_EPSS_DOWNLOAD_TIMEOUT,
        help="EPSS data download timeout, in seconds",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the plugin.

    Args:
        argv (list[str] | None, optional): Command-line arguments. Defaults to
            `None` (uses `sys.argv`).

    Returns:
        int: Status code for the plugin (0 on success, 1 on error).
    """
    parser = _argument_parser()
    args = parser.parse_args(argv)

    try:
        epss_data_file = args.cache_dir / EPSS_FILENAME
        update_epss_data(args.epss_url, epss_data_file, args.timeout)
        dump_updated_results(load_epss_data(epss_data_file), args.output)
    except TrivyPluginEPSSError as ex:
        logging.error(ex)
        # Consume rest of stdin to avoid blocking pipe in case of error
        for _ in sys.stdin:
            pass  # pragma: nocover
        return 1

    return 0


if __name__ == "__main__":  # pragma: nocover
    sys.exit(main())
