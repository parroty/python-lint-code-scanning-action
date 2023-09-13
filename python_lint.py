#!/usr/bin/env python3

"""
Lint Python files using your choice of linter.

Get output in SARIF, for upload to GitHub Code Scanning.

Written by Field Services, GitHub

Copyright (c) GitHub, 2023
"""

import sys
import logging
from argparse import ArgumentParser
from pathlib import Path
from subprocess import run
import json
from typing import Union
import re


LOG = logging.getLogger(__name__)


def flake8_linter(target: Path, output_filename: str) -> None:
    """Run the flake8 linter.
    
    In contrast to the other linters, flake8 has plugin architecture.

    We rely on the 'sarif' formatter being installed, which is part of this package.
    """
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
                "rules": [],
            }
        },
        "results": [
        ],
    }

    for result in results:
        rule_id = f'ruff/{result["code"]}'
        filename = result["filename"]
        message = result["message"]

        start_line = result["location"]["row"]
        start_column = result["location"]["column"]
        end_line = result["end_location"]["row"]
        end_column = result["end_location"]["column"]

        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(filename).resolve().absolute().as_uri(),
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_column,
                            "endLine": end_line,
                            "endColumn": end_column,
                        }
                    }
                }
            ],
            # TODO: think about how to add "fix" into the SARIF
            # Code Scanning doesn't do anything with it, so it isn't a high priority
        }

        sarif_run["results"].append(sarif_result)

        # append rule ID and label to the SARIF
        rules = sarif_run["tool"]["driver"]["rules"]
        
        if rule_id not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": rule_id,
                },
            }
            rules.append(sarif_rule)

    return sarif_run


def ruff_linter(target: Path, *args) -> dict:
    """Run the ruff linter."""
    from ruff import __main__ as ruff
    try:
        ruff_exe = ruff.find_ruff_bin()
    except AttributeError:
        ruff_exe = "ruff" if sys.platform != "win32" else "ruff.exe"

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
        rule_id = f'pylint/{result["message-id"]}'

        # append result to SARIF
        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": result["message"],
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target.resolve().parent.absolute().joinpath(result["path"]).as_uri(),
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

        # append rule ID and label to the SARIF
        rules = sarif_run["tool"]["driver"]["rules"]
        
        if rule_id not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": result["symbol"],
                },
            }
            rules.append(sarif_rule)

    return sarif_run


def pylint_linter(target: Path, *args) -> dict:
    """Run the pylint linter."""
    process = run(["pylint", "--output-format=json", "--recursive=y", target.absolute().as_posix()], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from pylint")
        return None

    # process STDOUT
    results = json.loads(process.stdout.decode("utf-8"))

    # format the pylint JSON into SARIF
    sarif_run = pylint_format_sarif(results, target)

    return sarif_run


def mypy_format_sarif(mypy_results: str) -> dict:
    """Convert MyPy output into SARIF."""
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

    # regex to remove specifics from messages to auto-generate rule IDs
    remove_quotations = re.compile(r'"[^"]*"')
    remove_numbers = re.compile(r"\d+")

    mypy_to_sarif_levels = {
        "error": "error",
        "warning": "warning",
        "note": "note"
    }

    for result in mypy_results.split("\n"):
        if not result:
            continue

        # NOTE: assumes no filename contains " :", may need to be addressed if that causes issues
        location, message = result.split(": ", 1)

        # NOTE: assumes we're using `--show-error-end`, which gives the end line/column too
        filename, start_line, start_column, end_line, end_column, *_ = location.split(":") + [1, None, None]

        level, rule_msg = message.split(": ", 1)

        rule_text, rule_id = rule_msg.split("  [", 1)
        
        rule_id = rule_id.rstrip("]")
        rule_id = f"mypy/{rule_id}"

        rule_text = remove_quotations.sub('"..."', rule_text)
        rule_text = remove_numbers.sub("N", rule_text)

        sarif_level = mypy_to_sarif_levels.get(level, "note")

        sarif_result = {
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": rule_msg,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(filename).resolve().absolute().as_uri(),
                        },
                        "region": {
                            "startLine": int(start_line),
                            "startColumn": int(start_column),
                            "endLine": int(end_line) if end_line is not None else start_line,
                            "endColumn": int(end_column) if end_column is not None else start_column,
                        }
                    }
                }
            ]
        }

        sarif_run["results"].append(sarif_result)

        # append the rule if we haven't already recorded it in the rules array
        rules = sarif_run["tool"]["driver"]["rules"]
        if rule_id not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": rule_text,
                },
            }
            rules.append(sarif_rule)

    return sarif_run


def mypy_linter(target: Path, output_filename: str) -> dict:
    """Run the mypy linter."""
    mypy_args = ["--ignore-missing-imports", "--no-error-summary", "--no-pretty", "--show-error-codes", "--show-column-numbers", "--show-error-end", "--show-absolute-path"]

    process = run(["mypy", *mypy_args, target.absolute().as_posix()], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from mypy")
        return None

    sarif_run = mypy_format_sarif(process.stdout.decode("utf-8"))

    return sarif_run


def pyright_format_sarif(results: dict) -> dict:
    pyright_version = results["version"]

    sarif_run = {
        "tool": {
            "driver": {
                "name": f"Pyright {pyright_version}",
                "rules": [],
            }
        },
        "results": [
        ],
    }

    for diagnostic in results["generalDiagnostics"]:
        filename = diagnostic["file"]
        message = diagnostic["message"]
        rule_id = f'pyright/{diagnostic["rule"]}' if "rule" in diagnostic else "pyright/builtIn"

        start_line = diagnostic["range"]["start"]["line"] + 1
        start_column = diagnostic["range"]["start"]["character"] + 1
        end_line = diagnostic["range"]["end"]["line"] + 1
        end_column = diagnostic["range"]["end"]["character"] + 1

        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": message,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(filename).resolve().absolute().as_uri(),
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_column,
                            "endLine": end_line,
                            "endColumn": end_column,
                        }
                    }
                }
            ]
        }

        sarif_run["results"].append(sarif_result)

        # append the rule if we haven't already recorded it in the rules array
        rules = sarif_run["tool"]["driver"]["rules"]
        if rule_id not in [rule["id"] for rule in rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": rule_id,
                },
            }
            rules.append(sarif_rule)

    return sarif_run


def pyright_linter(target: Path, output_filename: str) -> dict:
    """Run the pyright linter."""
    process = run(["pyright", "--outputjson", target.absolute().as_posix()], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from pyright")
        return None

    # process STDOUT
    results = json.loads(process.stdout.decode("utf-8"))

    # format the pyright JSON into SARIF
    sarif_run = pyright_format_sarif(results)

    return sarif_run


def pytype_format_sarif(results: str) -> dict:
    """Convert PyType output into SARIF."""

    sarif_run = {
        "tool": {
            "driver": {
                "name": "Pytype",
                "rules": [],
            }
        },
        "results": [
        ],
    }

    pytype_re = re.compile(r'File "(?P<filename>[^"]+)", line (?P<line>\d+), in (?P<scope>\S+): (?P<message>.*) \[(?P<rule>[a-z-]+)\]')

    for line in results.split("\n"):
        if match := pytype_re.search(line):
            filename = match.group("filename")
            line_number = int(match.group("line"))
            scope = match.group("scope")
            message = match.group("message")
            rule = match.group("rule")

            rule_id = f"pytype/{rule}"

            sarif_result = {
                "ruleId": rule_id,
                "level": "note",
                "message": {
                    "text": message,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": Path(filename).resolve().absolute().as_uri(),
                            },
                            "region": {
                                "startLine": line_number,
                                "startColumn": 1,
                                "endLine": line_number,
                                "endColumn": 1,
                            }
                        }
                    }
                ],
            }

            sarif_run["results"].append(sarif_result)

            # append the rule if we haven't already recorded it in the rules array
            rules = sarif_run["tool"]["driver"]["rules"]
            if rule_id not in [rule["id"] for rule in rules]:
                sarif_rule = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": rule_id,
                    },
                }
                rules.append(sarif_rule)

    return sarif_run


def pytype_linter(target: Path, *args) -> dict:
    """Run the pytype linter."""
    process = run(["pytype", "--exclude", ".pytype/", "--", target.absolute().as_posix()], capture_output=True)

    if process.stderr:
        LOG.error("STDERR: %s", process.stderr.decode("utf-8"))
        return None

    if not process.stdout:
        LOG.error("No output from pytype")
        return None

    # process STDOUT
    results = process.stdout.decode("utf-8")

    sarif_run = pytype_format_sarif(results)

    return sarif_run


LINTERS = {"pylint": pylint_linter, "ruff": ruff_linter, "flake8": flake8_linter, "mypy": mypy_linter, "pyright": pyright_linter}

# pytype is only supported on Python 3.10 and below, at the time of writing
if sys.version_info[0] == 3 and sys.version_info[1] <= 10:
    LINTERS["pytype"] = pytype_linter


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
        LOG.debug("Running %s", linter)

        sarif_run = LINTERS[linter](Path(args.target).absolute(), args.output)

        if sarif_run is not None:
            sarif["runs"].append(sarif_run)

    # output SARIF
    with open(f"{args.output}", "w") as sf:
        json.dump(sarif, sf, indent=2)


if __name__ == "__main__":
    main()
