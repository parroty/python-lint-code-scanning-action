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

    process = run(["flake8", target, "--format", "sarif"], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from flake8")
        return None

    # process STDOUT
    sarif = json.loads(process.stdout.decode("utf-8"))

    return sarif["runs"][0]


def ruff_format_sarif(results: list[dict[str, Union[str,int]]]) -> dict:
    sarif_run = {
        "tool": {
            "driver": {
                "name": "Ruff",
            }
        },
        "results": [
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

        sarif_run["results"].append(sarif_result)

    return sarif_run


def ruff_linter(target: Path, *args) -> dict:
    """Run the ruff linter."""
    LOG.debug("Running ruff")

    from ruff import __main__ as ruff
    ruff_exe = ruff.find_ruff_bin()

    # call ruff, capture STDOUT and STDERR using subprocess
    process = run([ruff_exe, target, "--format", "json"], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from ruff")
        return None

    # process STDOUT
    results = json.loads(process.stdout.decode("utf-8"))

    # format the ruff JSON into SARIF
    sarif_run = ruff_format_sarif(results)

    return sarif_run


def pylint_format_sarif(results: list[dict[str, Union[str,int]]], target: Path) -> dict:
    sarif_run = {
        "tool": {
            "driver": {
                "name": "Pylint",
                "rules": [],
            }
        },
        "results": [
        ],
    }

    for result in results:
        # append rule ID and label to the SARIF
        rules = sarif_run["tool"]["driver"]["rules"]
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

        sarif_run["results"].append(sarif_result)

    return sarif_run


def pylint_linter(target: Path, *args) -> dict:
    """Run the pylint linter."""
    LOG.debug("Running pylint")

    process = run(["pylint", "--output-format=json", "--recursive=y", target.absolute().as_posix()], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from pylint")
        return None

    # process STDOUT
    results = json.loads(process.stdout.decode("utf-8"))

    LOG.debug(results)

    # format the pylint JSON into SARIF
    sarif_run = pylint_format_sarif(results, target)

    return sarif_run


def mypy_format_sarif(junit_xml_file: str) -> dict:
    """Convert JUnit XML output into SARIF."""
    sarif_run = {
        "tool": {
            "driver": {
                "name": "MyPy",
                "rules": [],
            }
        },
        "results": [
        ],
    }

    # read in XML from filename
    with open(junit_xml_file) as xf:
        xml_data = xf.read()

        # convert to JSON
        from junitparser import TestCase, TestSuite, JUnitXml
        junit_xml = JUnitXml.fromstring(xml_data)

        for suite in junit_xml:
            for case in suite:
                LOG.debug(dir(case))
                LOG.debug(case)

                continue

                sarif_result = {
                    "ruleId": case.type,
                    "level": "note",
                    "message": {
                        "text": case.message,
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": case.classname,
                                },
                                "region": {
                                    "startLine": case.line,
                                    "startColumn": case.column,
                                    "endLine": case.line,
                                    "endColumn": case.column,
                                }
                            }
                        }
                    ]
                }

                sarif_run["results"].append(sarif_result)

                # append the rule if we haven't already recorded it in the rules array
                rules = sarif_run["tool"]["driver"]["rules"]
                if case.name not in [rule["id"] for rule in rules]:
                    sarif_rule = {
                        "id": case.name,
                        "shortDescription": {
                            "text": case.name,
                        },
                    }
                    rules.append(sarif_rule)

    return sarif_run


def mypy_linter(target: Path, output_filename: str) -> dict:
    """Run the mypy linter."""

    LOG.debug("Running mypy")

    mypy_junit_xml = Path(output_filename).with_suffix(".xml")

    process = run(["mypy", "--ignore-missing-imports", "--junit-xml", mypy_junit_xml.as_posix(), target.absolute().as_posix()], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from mypy")
        return None

    LOG.debug(open(mypy_junit_xml).read())

    sarif_run = mypy_format_sarif(mypy_junit_xml)

    return sarif_run


LINTERS = {"pylint": pylint_linter, "ruff": ruff_linter, "flake8": flake8_linter, "mypy": mypy_linter}


def add_args(parser: ArgumentParser) -> None:
    """Add arguments to the parser."""
    parser.add_argument("linter", choices=LINTERS.keys(), nargs="+", help="The linter(s) to use")
    parser.add_argument("--target", "-t", default=".", required=False, help="Target path for the linter")
    parser.add_argument("--output", "-o", default="python_linter.sarif", required=False, help="Output filename")
    parser.add_argument("--debug", "-d", action="store_true", required=False, help="Enable debug logging")


def main() -> None:
    """Main entry point for the application."""
    parser = ArgumentParser(description="__description__")
    add_args(parser)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    if any([linter not in LINTERS for linter in args.linter]):
        LOG.error(f"Invalid linter choice: {args.linter}")
        exit(1)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
        ]
    }

    for linter in args.linter:
        LOG.info("Running %s", linter)

        sarif_run = LINTERS[linter](Path(args.target).absolute(), args.output)

        if sarif_run is not None:
            sarif["runs"].append(sarif_run)

    # output SARIF
    with open(f"{args.output}", "w") as sf:
        json.dump(sarif, sf, indent=2)


if __name__ == "__main__":
    main()
