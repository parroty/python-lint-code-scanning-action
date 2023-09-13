# Python Linting Action

> ⚠️ this is work in progress ⚠️
> 🚨 it does not use an open source license yet, and comes with no support guarantees at all - it is pre-release and still in alpha/testing 🚨

This Action and Python script lets you run one of several Python linters and type checkers, and upload the results to GitHub's Code Scanning.

## Supported linters

- [Flake8](https://flake8.pycqa.org/en/latest/)
- [Pylint](https://www.pylint.org/)
- [Ruff](https://beta.ruff.rs/)
- [Mypy](https://mypy.readthedocs.io/en/stable/)
- [Pytype](https://github.com/google/pytype/) - for Python 3.10 and below only
- [Pyright](https://github.com/microsoft/pyright)

## Requirements

- Python 3.7 or higher
- For Pytype, Python 3.10 or lower
- GitHub Actions

## Usage

### Command line

First install the Flake8 SARIF formatter, if you are using Flake8:

```bash
python3 -m pip install ./flake8_sarif_formatter
```

Then run the linter:

```bash
python3 ./python_lint <linter> [<options>]
```

The linter/type checker can be one or more of `flake8`, `pylint`, `ruff`, `mypy`, `pytype`, `pyright`.

### Action

```yaml
use: aegilops/python-lint-code-scanning-action@main
with:
  linter: flake8
```

You can run it with more than one linter using a matrix:

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        linter: [flake8, pylint, ruff, mypy, pytype, pyright]
    steps:
      - use: aegilops/python-lint-code-scanning-action@main
        with:
          linter: ${{ matrix.linter }}
```

Similarly, you can run it with more than one Python version:

```yaml
jobs:
  lint:

    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.7, 3.8, 3.9, 3.10]
    steps:
      - use: aegilops/python-lint-code-scanning-action@main
        with:
          linter: flake8
          python-version: ${{ matrix.python-version }}
```

You could even combine both.

If you want to use plugins for one of the linters, you can install that before running the action, e.g.

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: python3 -mpip install flake8-bugbear
      - use: aegilops/python-lint-code-scanning-action@v1
        with:
          linter: flake8
```
