# trivy-plugin-epss

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/melmorabity/trivy-plugin-epss/main.svg)](https://results.pre-commit.ci/latest/github/melmorabity/trivy-plugin-epss/main)
[![CI](https://github.com/melmorabity/trivy-plugin-epss/actions/workflows/ci.yml/badge.svg)](https://github.com/melmorabity/trivy-plugin-epss/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/melmorabity/trivy-plugin-epss/graph/badge.svg)](https://codecov.io/gh/melmorabity/trivy-plugin-epss)

A [Trivy](https://trivy.dev/latest/) plugin that enhances vulnerability scan results with [EPSS (Exploit Prediction Scoring System)](https://www.first.org/epss/) data, to prioritize risks based on exploit likelihood.

## How it works

The plugin downloads and caches [the latest EPSS dataset](https://www.first.org/epss/data_stats) (updated daily by FIRST) if the local cache is missing or older than 24 hours.

It then reads Trivy's scan results in JSON format from standard input and, for each vulnerability, adds the corresponding EPSS score and metadata if available. For example:

```json
{
  ...,
  "Results": [
    ...,
    "Vulnerabilities": [
      ...,
      {
        "VulnerabilityID": "CVE-2023-34152",
        ...,
        "EPSS": {
          "score": 0.70203,
          "percentile": 0.98573,
          "model_version": "v2025.03.14",
          "score_date": "2025-05-30T12:55:00Z"
        }
      },
      ...
    ],
  ],
  ...
}
```

> **Note**: Only Trivy's JSON output format is supported.

## Installation

The plugin is written in Python and requires Python 3.10 or newer. To install it, run the following command:

```console
trivy plugin install github.com/melmorabity/trivy-plugin-epss@v1.0.0
```

## Usage

### Supported options

```console
$ trivy epss --help
usage: trivy epss [-h] [-o OUTPUT] [--epss-url EPSS_URL] [--cache-dir CACHE_DIR]

A Trivy plugin that enhances vulnerability scan results with EPSS data

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   output file name (default: None)
  --epss-url EPSS_URL   EPSS data URL (must point to a Gzipped file) (default:
                        https://epss.empiricalsecurity.com/epss_scores-current.csv.gz)
  --cache-dir CACHE_DIR
                        EPSS data cache directory (default: ~/.cache/trivy/epss)
```

### Examples

The following commands are equivalent and output Trivy scan results enriched with EPSS data.

```console
trivy image --format json --output plugin=epss --output-plugin-arg "--cache-dir=/tmp --output with_epss.json" node:22
```

```console
trivy image --format json node:22 | trivy epss --cache-dir=/tmp --output with_epss.json
```

> **Note**: Make sure to use `--format json` when scanning with Trivy.

## Copyright and license

© 2025 Mohamed El Morabity

Licensed under the [GNU GPL, version 3.0 or later](LICENSE).

This project has no affiliation with Aqua Security or FIRST.org.
