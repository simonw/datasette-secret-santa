# datasette-secret-santa

[![PyPI](https://img.shields.io/pypi/v/datasette-secret-santa.svg)](https://pypi.org/project/datasette-secret-santa/)
[![Changelog](https://img.shields.io/github/v/release/simonw/datasette-secret-santa?include_prereleases&label=changelog)](https://github.com/simonw/datasette-secret-santa/releases)
[![Tests](https://github.com/simonw/datasette-secret-santa/workflows/Test/badge.svg)](https://github.com/simonw/datasette-secret-santa/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/datasette-secret-santa/blob/main/LICENSE)

Run a secret santa using Datasette

## Installation

Install this plugin in the same environment as Datasette.

    datasette install datasette-secret-santa

## Usage

This plugin requires a database called `santa.db`. You can run it and create such a database like this:

    datasette santa.db --create

It expects to be the only plugin installed, and will take over the `/` homepage.

To create a new Secret Santa, visit `/santa/create_secret_santa`.

## Development

To set up this plugin locally, first checkout the code. Then create a new virtual environment:

    cd datasette-secret-santa
    python3 -m venv venv
    source venv/bin/activate

Now install the dependencies and test dependencies:

    pip install -e '.[test]'

To run the tests:

    pytest
