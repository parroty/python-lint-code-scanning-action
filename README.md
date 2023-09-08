# Python Linting Action

## Usage

### Command line

First install the Flake8 SARIF formatter, if you are using Flake8:

```bash
python3 -m pip install ./flake8_sarif_formatter
```

Then run the linter:

```bash
python3 ./python_lint <linter>
```

The linter can be one of `flake8`, `pylint`, or `ruff`.

### Action

```yaml
use: aegilops/python-lint-code-scanning-action@v1
with:
  linter: flake8
```
