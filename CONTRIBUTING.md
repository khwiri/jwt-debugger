## How to Contribute

Thank you for considering contributing to jwt-debugger!

Please take a moment to review this document in order to make the contributing process as easy as possible.

## Getting Started

If you've noticed a bug or have a feature request then please [create an issue](https://github.com/khwiri/jwt-debugger/issues/new/choose).
If it's something you want to try implementing then [fork the repo](https://docs.github.com/en/get-started/quickstart/fork-a-repo) and go for it.

## Submitting Changes

The rest of this document should help get your environment ready so that you can start
making changes. Once your changes are ready to go or you just want some feedback then
create a pull request. This project uses [keeping a changelog](ttps://keepachangelog.com/en/1.0.0/)
as the change log format. It would be helpful to include an entry in the *Unreleased*
section of [CHANGELOG.md](./CHANGELOG.md) with a link to your pull request.

## Prerequisites

1. Python and preferably [pyenv](https://github.com/pyenv/pyenv) for swapping between supported versions
1. [Pipenv](https://github.com/pypa/pipenv)

## Development Setup

Use the following command to install dependencies.

```
pipenv sync --dev
```

Use the following command to install jwt-debugger as an editable package.
See [Pip Editable Installs](https://pip.pypa.io/en/stable/topics/local-project-installs/#editable-installs) for more information.

```
pipenv run pip install --editable .
```

Use the following command to run locally.

```
pipenv run jwt-debugger --help
```

## Running Tests

```
pipenv run python -m unittest
```
