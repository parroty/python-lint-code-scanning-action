#!/usr/bin/env python3

"""
Lint Python files using your choice of linter - flake8, pylint or ruff.

Get output in SARIF, for upload to GitHub Code Scanning.

Written by Field Services, GitHub

Copyright (c) GitHub, 2023
"""

import logging
from argparse import ArgumentParser
from pathlib import Path
from subprocess import run
import json
from typing import Union


LOG = logging.getLogger(__name__)


def flake8_linter(target: Path, output_filename: str) -> None:
    """Run the flake8 linter.
    
    In contrast to the other linters, flake8 has plugin architecture.

    We rely on the 'sarif' formatter being installed, which is part of this package.
    """
    LOG.debug("Running flake8")

    from flake8 import __version__ as flake8_version
    from flake8.api import legacy as flake8_api

    LOG.debug("flake8 version: %s", flake8_version)

    # run flake8, outputting SARIF
    runner = flake8_api.get_style_guide(format="sarif", output_file=output_filename)
    runner.check_files([target.absolute().as_posix()])

    return None


def ruff_format_sarif(results: list[dict[str, Union[str,int]]]) -> dict:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Ruff",
                    }
                },
                "results": [
                ],
            }
        ],
    }

    for result in results:
        sarif_result = {
            "ruleId": result["code"],
            "level": "note",
            "message": {
                "text": result["message"],
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result["filename"],
                        },
                        "region": {
                            "startLine": result["location"]["row"],
                            "startColumn": result["location"]["column"],
                            "endLine": result["end_location"]["row"],
                            "endColumn": result["end_location"]["column"],
                        }
                    }
                }
            ],
            # TODO: think about how to add "fix" into the SARIF
            # Code Scanning doesn't do anything with it, so it isn't a high priority
        }

        sarif["runs"][0]["results"].append(sarif_result)

    return sarif


def ruff_linter(target: Path, *args) -> dict:
    """Run the ruff linter."""
    LOG.debug("Running ruff")

    from ruff import __main__ as ruff
    ruff_exe = ruff.find_ruff_bin()

    # call ruff, capture STDOUT and STDERR using subprocess
    process = run([ruff_exe, target, "--format", "json"], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return

    if not process.stdout:
        LOG.error("No output from ruff")
        return

    # process STDOUT
    results = json.loads(process.stdout.decode("utf-8"))

    # format the ruff JSON into SARIF
    sarif = ruff_format_sarif(results)

    return sarif


def pylint_format_sarif(results: list[dict[str, Union[str,int]]], target: Path) -> dict:
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Pylint",
                        "rules": [],
                    }
                },
                "results": [
                ],
            }
        ],
    }

    for result in results:
        # append rule ID and label to the SARIF
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        if result["message-id"] not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": result["message-id"],
                "shortDescription": {
                    "text": result["symbol"],
                },
            }
            rules.append(sarif_rule)

        # append result to SARIF
        sarif_result = {
            "ruleId": result["message-id"],
            "level": "note",
            "message": {
                "text": result["message"],
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            # TODO: this is relative to the target directory
                            "uri": target.absolute().joinpath(result["path"]).as_uri(),
                        },
                        "region": {
                            "startLine": result["line"],
                            "startColumn": result["column"]+1,
                            "endLine": result["endLine"] if result["endLine"] is not None else result["line"],
                            "endColumn": result["endColumn"] if result["endColumn"] is not None else result["column"]+1,
                        }
                    }
                }
            ],
            # TODO: think about how to add "fix" into the SARIF
            # Code Scanning doesn't do anything with it, so it isn't a high priority
        }

        sarif["runs"][0]["results"].append(sarif_result)

    return sarif


def pylint_linter(target: Path, *args) -> dict:
    """Run the pylint linter."""
    LOG.debug("Running pylint")

    process = run(["pylint", "--output-format=json", "--recursive=y", target.absolute().as_posix()], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return

    if not process.stdout:
        LOG.error("No output from pylint")
        return

    # process STDOUT
    results = json.loads(process.stdout.decode("utf-8"))

    LOG.debug(results)

    # format the pylint JSON into SARIF
    sarif = pylint_format_sarif(results, target)

    return sarif


LINTERS = {"pylint": pylint_linter, "ruff": ruff_linter, "flake8": flake8_linter}


def add_args(parser: ArgumentParser) -> None:
    """Add arguments to the parser."""
    parser.add_argument("linters", choices=LINTERS.keys(), nargs="+", help="The linter(s) to use")
    parser.add_argument("--target", "-t", default=".", required=False, help="Target path for the linter")
    parser.add_argument("--output", "-o", default="python_linter.sarif", required=False, help="Output filename")
    parser.add_argument("--debug", "-d", action="store_true", required=False, help="Enable debug logging")


def main() -> None:
    """Main entry point for the application."""
    parser = ArgumentParser(description="__description__")
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    if args.linter not in LINTERS:
        LOG.error(f"Invalid linter: {args.linter}")
        exit(1)

    sarif = LINTERS[args.linter](Path(args.target).absolute(), args.output)

    if sarif is not None:
        # output the results to a file, for later upload
        with open(args.output, "w") as sf:
            json.dump(sarif, sf, indent=2)


if __name__ == "__main__":
    main()
