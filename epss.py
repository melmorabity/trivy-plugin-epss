#!/usr/bin/env python3

# SPDX-FileCopyrightText: © 2025 Mohamed El Morabity
# SPDX-License-Identifier: GPL-3.0-or-later

"""A Trivy plugin that enhances vulnerability scan results with EPSS data."""

from __future__ import annotations

import csv
import errno
import json
import logging
import re
import sys
import time
import urllib.request
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from csv import Error as CSVError
from gzip import BadGzipFile, GzipFile
from json import JSONDecodeError
from pathlib import Path
from typing import Any
from urllib.error import URLError

DEFAULT_EPSS_DATA_URL = (
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)
DEFAULT_EPSS_CACHE_DIR = Path.home() / ".cache" / "trivy" / "epss"
EPSS_FILENAME = "epss.csv"


logging.basicConfig(
    level=logging.ERROR,
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    format="%(asctime)s\t%(levelname)s\t[epss] %(message)s",
    stream=sys.stderr,
)


class TrivyPluginEPSSError(Exception):
    """Base class for exceptions raised by the Trivy plugin."""


def _update_epss_data(epss_data_url: str, target_file: Path) -> None:
    # Check if file exists and its age
    if (
        target_file.is_file()
        and (time.time() - target_file.stat().st_mtime) < 24 * 60 * 60
    ):
        return

    target_file.parent.mkdir(exist_ok=True, parents=True)
    try:
        with (
            urllib.request.urlopen(epss_data_url) as response,  # noqa: S310
            GzipFile(fileobj=response) as gzip_file,
            target_file.open("wb") as writer,
        ):
            writer.write(gzip_file.read())
    except URLError as ex:
        raise TrivyPluginEPSSError(
            f"Failed to download EPSS data: {ex}"
        ) from None
    except BadGzipFile:
        raise TrivyPluginEPSSError("EPSS data are not Gzipped") from None
    except OSError:
        raise TrivyPluginEPSSError(
            f"Unable to write EPSS data to {target_file}"
        ) from None


def _load_epss_data(csv_file: Path) -> dict[str, dict[str, Any]]:
    data = {}
    model_version = None
    score_date = None

    try:
        with csv_file.open("r", encoding="utf-8") as csvfile:
            # Read metadata from the first line if present
            if match := re.match(
                r"\s*#\s*model_version\s*:\s*(.+?)\s*,"
                r"score_date\s*:\s*(.+?)\s*$",
                csvfile.readline(),
            ):
                model_version, score_date = match.groups()
            else:
                csvfile.seek(0)

            csv_reader = csv.reader(
                row
                for row in csvfile
                if re.match(r"\s*CVE-\d{4}-\d{4,}\b", row)
            )
            for fields in csv_reader:
                if len(fields) != 3:  # noqa: PLR2004
                    continue
                cve, score, percentile = fields
                data[cve] = {
                    "score": float(score),
                    "percentile": float(percentile),
                    "model_version": model_version,
                    "score_date": score_date,
                }
    except OSError as ex:
        raise TrivyPluginEPSSError(
            f"Unable to read EPSS data from {csv_file}: {ex}"
        ) from None
    except (CSVError, UnicodeError) as ex:
        raise TrivyPluginEPSSError(f"Malformed EPSS data: {ex}") from None

    return data


def _dump_updated_results(
    epss_data: dict[str, dict[str, Any]], output_file: Path | None
) -> None:
    try:
        data = json.loads(sys.stdin.read())
    except JSONDecodeError:
        raise TrivyPluginEPSSError("Invalid JSON scan result") from None

    for result in data.get("Results", []):
        vulnerabilities = result.get("Vulnerabilities", [])
        for vulnerability in vulnerabilities:
            cve = vulnerability.get("VulnerabilityID")
            if cve and cve in epss_data:
                vulnerability.update({"EPSS": epss_data[cve]})

    if output_file:
        with output_file.open("w", encoding="UTF-8") as writer:
            json.dump(data, writer, indent=2)
    else:
        try:
            json.dump(data, sys.stdout, indent=2)
        except OSError as ex:
            # Ignore Broken Pipe errors that may occur when the output is piped
            # and the downstream process closes early
            if ex.errno == errno.EPIPE:
                pass


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

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the plugin.

    Args:
        argv (list[str] | None, optional): Command-line arguments. Defaults to
            `None`.

    Returns:
        int: The status code for the plugin.
    """
    parser = _argument_parser()
    args = parser.parse_args(argv)

    try:
        epss_data_file = args.cache_dir / EPSS_FILENAME
        _update_epss_data(args.epss_url, epss_data_file)
        _dump_updated_results(_load_epss_data(epss_data_file), args.output)
    except TrivyPluginEPSSError as ex:
        logging.error(ex)
        for _ in sys.stdin:
            pass
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
