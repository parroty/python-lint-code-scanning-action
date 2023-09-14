"""Format Flake8 output as SARIF."""

import sys
import json
from flake8.formatting import base
from flake8.style_guide import Violation
from pathlib import Path


class SarifFormatter(base.BaseFormatter):
    """SARIF formatter for Flake8."""

    def after_init(self):
        self.sarif_results = []
        self.sarif_rules = []

    def stop(self):
        """Output the SARIF."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "Flake8", "rules": self.sarif_rules},
                    },
                    "results": self.sarif_results,
                }
            ],
        }

        json.dump(sarif, self.output_fd if self.output_fd is not None else sys.stdout, indent=2)

    def handle(self, error: Violation):
        """Convert the error into a SARIF result, and append it to the SARIF."""
        rule_id = f"flake8/{error.code}"

        sarif_result = {
            "ruleId": rule_id,
            "level": "note",
            "message": {
                "text": error.text,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": Path(error.filename).resolve().absolute().as_uri(),
                        },
                        "region": {
                            "startLine": error.line_number,
                            "startColumn": error.column_number,
                            "endLine": error.line_number,
                            "endColumn": error.column_number,
                        },
                    }
                }
            ],
        }

        self.sarif_results.append(sarif_result)

        if error.code not in [rule["id"] for rule in self.sarif_rules]:
            sarif_rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": error.code,
                },
            }

            self.sarif_rules.append(sarif_rule)
