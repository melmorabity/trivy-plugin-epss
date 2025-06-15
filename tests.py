# SPDX-FileCopyrightText: © 2025 Mohamed El Morabity
# SPDX-License-Identifier: GPL-3.0-or-later


from __future__ import annotations

import gzip
import json
import logging
import os
import sys
import time
import typing
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any, Protocol
from urllib.error import URLError

import pytest

import epss
from epss import TrivyPluginEPSSError

if typing.TYPE_CHECKING:
    from unittest.mock import Mock

    from pyfakefs.fake_filesystem import FakeFilesystem
    from pytest_mock.plugin import MockerFixture


@pytest.fixture(autouse=True)
def fake_filesystem(fs: FakeFilesystem) -> FakeFilesystem:
    return fs


@pytest.fixture
def epss_csv() -> str:
    return (
        "# model_version: 2025.06,score_date: 2025-06-14\n"
        "CVE-2025-1234,0.9,99.9\n"
        "CVE-2025-5678,0.1,0.001\n"
        "CVE-2025-9012,9e-05,0.5\n"
    )


@pytest.fixture
def epss_data() -> dict[str, Any]:
    return {
        "CVE-2025-1234": {
            "score": 0.9,
            "percentile": 99.9,
            "model_version": "2025.06",
            "score_date": "2025-06-14",
        },
        "CVE-2025-5678": {
            "score": 0.1,
            "percentile": 0.001,
            "model_version": "2025.06",
            "score_date": "2025-06-14",
        },
        "CVE-2025-9012": {
            "score": 9e-5,
            "percentile": 0.5,
            "model_version": "2025.06",
            "score_date": "2025-06-14",
        },
    }


@pytest.fixture
def epss_csv_file() -> Path:
    path = Path("/epss/data.csv")

    assert not path.parent.exists()
    assert not path.is_file()

    return path


@pytest.fixture
def empty_epss_csv_file(epss_csv_file: Path) -> Path:
    epss_csv_file.parent.mkdir(parents=True, exist_ok=True)
    epss_csv_file.touch()

    assert epss_csv_file.parent.is_dir()
    assert epss_csv_file.is_file()

    return epss_csv_file


class EpssCsvFileWithContentFixture(Protocol):
    def __call__(self, content: str | None = ...) -> Path: ...


@pytest.fixture
def epss_csv_file_with_content(
    epss_csv: str, empty_epss_csv_file: Path
) -> EpssCsvFileWithContentFixture:
    def _epss_csv_file_with_content(content: str | None = None) -> Path:
        text = content if content is not None else epss_csv
        empty_epss_csv_file.write_text(text, encoding="utf-8")
        return empty_epss_csv_file

    return _epss_csv_file_with_content


class UrlopenFixture(Protocol):
    def __call__(
        self, content: str | URLError, gzipped: bool = ...
    ) -> Mock: ...


@pytest.fixture
def urlopen(mocker: MockerFixture) -> UrlopenFixture:
    def _urlopen(content: str | URLError, gzipped: bool = True) -> Mock:
        if isinstance(content, Exception):
            return mocker.patch(
                "epss.urllib.request.urlopen", side_effect=content
            )

        if gzipped:
            mock_response = BytesIO(gzip.compress(content.encode("utf-8")))
        else:
            mock_response = BytesIO(content.encode("utf-8"))

        return mocker.patch(
            "epss.urllib.request.urlopen", return_value=mock_response
        )

    return _urlopen


@pytest.fixture
def trivy_json_result() -> dict[str, Any]:
    return {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2025-1234"},
                    {"VulnerabilityID": "CVE-2025-5678"},
                    {"VulnerabilityID": "CVE-1999-0001"},
                ]
            }
        ]
    }


@pytest.fixture
def updated_trivy_json_result() -> dict[str, Any]:
    return {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-1234",
                        "EPSS": {
                            "score": 0.9,
                            "percentile": 99.9,
                            "model_version": "2025.06",
                            "score_date": "2025-06-14",
                        },
                    },
                    {
                        "VulnerabilityID": "CVE-2025-5678",
                        "EPSS": {
                            "score": 0.1,
                            "percentile": 0.001,
                            "model_version": "2025.06",
                            "score_date": "2025-06-14",
                        },
                    },
                    {"VulnerabilityID": "CVE-1999-0001"},
                ]
            }
        ]
    }


def test_no_update_epss_data(
    epss_csv_file_with_content: EpssCsvFileWithContentFixture,
    urlopen: UrlopenFixture,
) -> None:
    network_mock = urlopen("")

    epss.update_epss_data("https://epss", epss_csv_file_with_content())

    network_mock.assert_not_called()


def test_create_epss_data(
    epss_csv_file: Path, epss_csv: str, urlopen: UrlopenFixture
) -> None:
    network_mock = urlopen(epss_csv)

    epss.update_epss_data("https://epss", epss_csv_file)

    network_mock.assert_called()
    assert epss_csv_file.parent.is_dir()
    assert epss_csv_file.is_file()
    with epss_csv_file.open("r") as reader:
        assert reader.read() == epss_csv


def test_update_epss_data(epss_csv: str, urlopen: UrlopenFixture) -> None:
    network_mock = urlopen(epss_csv)

    target_file = Path("/path/to/target.csv")
    target_file.parent.mkdir(parents=True)
    target_file.touch()
    target_file_mtime = time.time() - 25 * 60 * 60
    os.utime(target_file, (target_file_mtime, target_file_mtime))
    assert target_file.parent.is_dir()
    assert target_file.is_file()
    with target_file.open("r") as reader:
        assert reader.read() != epss_csv

    epss.update_epss_data("https://epss", target_file)

    network_mock.assert_called()
    with target_file.open("r") as reader:
        assert reader.read() == epss_csv


def test_update_epss_data_network_error(urlopen: UrlopenFixture) -> None:
    network_mock = urlopen(URLError(reason="An error occurred"))

    target_file = Path("/path/to/target.csv")
    assert not target_file.parent.exists()
    assert not target_file.exists()

    with pytest.raises(TrivyPluginEPSSError, match="An error occurred"):
        epss.update_epss_data("https://epss", target_file)

    network_mock.assert_called()
    assert not target_file.is_file()


def test_update_epss_data_gzip_error(
    epss_csv: str, urlopen: UrlopenFixture
) -> None:
    network_mock = urlopen(epss_csv, gzipped=False)

    target_file = Path("/path/to/target.csv")
    assert not target_file.parent.exists()
    assert not target_file.exists()

    with pytest.raises(
        TrivyPluginEPSSError, match="EPSS data are not gzipped"
    ):
        epss.update_epss_data("https://epss", target_file)

    network_mock.assert_called()
    assert target_file.parent.is_dir()
    assert not target_file.exists()


def test_update_epss_data_write_error(
    epss_csv: str, urlopen: UrlopenFixture, mocker: MockerFixture
) -> None:
    target_file = Path("/path/to/target.csv")
    network_mock = urlopen(epss_csv)
    assert not target_file.parent.exists()
    assert not target_file.exists()

    mocker.patch("pathlib.Path.open", side_effect=OSError("Permission denied"))

    with pytest.raises(
        TrivyPluginEPSSError, match="Unable to write EPSS data"
    ):
        epss.update_epss_data("https://epss", target_file)

    network_mock.assert_called()
    assert target_file.parent.is_dir()
    assert not target_file.exists()


def test_load_epss_data(
    epss_csv_file_with_content: EpssCsvFileWithContentFixture,
    epss_data: dict[str, Any],
) -> None:
    result = epss.load_epss_data(epss_csv_file_with_content())

    assert result == epss_data


def test_load_epss_data_without_header(
    epss_csv: str, epss_csv_file_with_content: EpssCsvFileWithContentFixture
) -> None:
    data = "\n".join(epss_csv.split("\n")[1:])
    result = epss.load_epss_data(epss_csv_file_with_content(content=data))

    assert result == {
        "CVE-2025-1234": {
            "score": 0.9,
            "percentile": 99.9,
            "model_version": None,
            "score_date": None,
        },
        "CVE-2025-5678": {
            "score": 0.1,
            "percentile": 0.001,
            "model_version": None,
            "score_date": None,
        },
        "CVE-2025-9012": {
            "score": 9e-5,
            "percentile": 0.5,
            "model_version": None,
            "score_date": None,
        },
    }


def test_load_epss_data_with_invalid_lines(
    epss_csv: str,
    epss_csv_file_with_content: EpssCsvFileWithContentFixture,
    epss_data: dict[str, Any],
) -> None:
    data = f'{epss_csv}\n\nCVE-1999-0001,"0.05",\nAnother invalid line\n'
    result = epss.load_epss_data(epss_csv_file_with_content(content=data))

    assert result == epss_data


def test_load_epss_data_file_missing(epss_csv_file: Path) -> None:
    with pytest.raises(
        TrivyPluginEPSSError,
        match=f"Unable to read EPSS data from {epss_csv_file}",
    ):
        epss.load_epss_data(epss_csv_file)


def test_dump_updated_results_to_stdout(
    capsys: pytest.CaptureFixture[str],
    epss_data: dict[str, Any],
    trivy_json_result: dict[str, Any],
    updated_trivy_json_result: dict[str, Any],
) -> None:
    sys.stdin = StringIO(json.dumps(trivy_json_result))

    epss.dump_updated_results(epss_data, None)
    captured = capsys.readouterr()
    assert json.loads(captured.out) == updated_trivy_json_result


def test_dump_updated_results_to_file(
    capsys: pytest.CaptureFixture[str],
    epss_data: dict[str, Any],
    trivy_json_result: dict[str, Any],
    updated_trivy_json_result: dict[str, Any],
) -> None:
    sys.stdin = StringIO(json.dumps(trivy_json_result))

    output_file = Path("/trivy/scans/result.json")
    output_file.parent.mkdir(parents=True)

    epss.dump_updated_results(epss_data, output_file)

    assert not capsys.readouterr().out
    with output_file.open("r") as reader:
        assert json.loads(reader.read()) == updated_trivy_json_result


def test_dump_updated_results_invalid_input(
    capsys: pytest.CaptureFixture[str], epss_data: dict[str, Any]
) -> None:
    sys.stdin = StringIO("Not a valid JSON")

    with pytest.raises(TrivyPluginEPSSError, match="Invalid JSON scan result"):
        epss.dump_updated_results(epss_data, None)

    assert not capsys.readouterr().out


def test_dump_updated_results_to_file_error(
    capsys: pytest.CaptureFixture[str],
    epss_data: dict[str, Any],
    trivy_json_result: dict[str, Any],
) -> None:
    sys.stdin = StringIO(json.dumps(trivy_json_result))

    output_file = Path("/trivy/scans/result.json")

    with pytest.raises(
        TrivyPluginEPSSError, match=f"Unable to write data to {output_file}"
    ):
        epss.dump_updated_results(epss_data, output_file)

    assert not capsys.readouterr().out


@pytest.mark.parametrize(
    ("output", "epss_url", "cache_dir"),
    [
        (None, None, None),
        ("/trivy/scans/result.json", None, None),
        (None, "https://epss", None),
        (None, None, "/trivy/cache"),
        (None, "https://epss", "/trivy/cache"),
        ("/trivy/scans/result.json", None, "/trivy/cache"),
        ("/trivy/scans/result.json", "https://epss", None),
        ("/trivy/scans/result.json", "https://epss", "/trivy/cache"),
    ],
)
def test_main_success(
    mocker: MockerFixture,
    epss_data: dict[str, Any],
    trivy_json_result: dict[str, Any],
    output: str,
    epss_url: str,
    cache_dir: str,
) -> None:
    update_epss_data_mock = mocker.patch("epss.update_epss_data")
    load_epss_data_mock = mocker.patch(
        "epss.load_epss_data", return_value=epss_data
    )
    dump_updated_results_mock = mocker.patch("epss.dump_updated_results")

    sys.stdin = StringIO(json.dumps(trivy_json_result))

    args: list[str] = []
    if output:
        args += ["--output", output]
    if epss_url:
        args += ["--epss-url", epss_url]
    if cache_dir:
        args += ["--cache-dir", cache_dir]

    status = epss.main(args)

    assert status == 0
    epss_data_file = (
        Path(cache_dir) if cache_dir else epss.DEFAULT_EPSS_CACHE_DIR
    ) / epss.EPSS_FILENAME
    update_epss_data_mock.assert_called_once_with(
        epss_url or epss.DEFAULT_EPSS_DATA_URL, epss_data_file
    )
    load_epss_data_mock.assert_called_once_with(epss_data_file)
    dump_updated_results_mock.assert_called_once_with(
        epss_data, Path(output) if output else None
    )


@pytest.mark.parametrize(
    "failing_func",
    [
        "epss.update_epss_data",
        "epss.load_epss_data",
        "epss.dump_updated_results",
    ],
)
def test_main_logs_and_returns_1_on_plugin_error(
    mocker: MockerFixture, failing_func: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR)

    mocker.patch(
        failing_func,
        side_effect=epss.TrivyPluginEPSSError("An error occurred"),
    )

    for func in {
        "epss.update_epss_data",
        "epss.load_epss_data",
        "epss.dump_updated_results",
    } - {failing_func}:
        mocker.patch(func)

    sys.stdin = StringIO("{}")
    status = epss.main([])

    assert status == 1
    assert any("An error occurred" in msg for msg in caplog.messages)
