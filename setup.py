from setuptools import setup
import os

VERSION = "0.1"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="datasette-secret-santa",
    description="Run a secret santa using Datasette",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/simonw/datasette-secret-santa",
    project_urls={
        "Issues": "https://github.com/simonw/datasette-secret-santa/issues",
        "CI": "https://github.com/simonw/datasette-secret-santa/actions",
        "Changelog": "https://github.com/simonw/datasette-secret-santa/releases",
    },
    license="Apache License, Version 2.0",
    classifiers=[
        "Framework :: Datasette",
        "License :: OSI Approved :: Apache Software License",
    ],
    version=VERSION,
    packages=["datasette_secret_santa"],
    entry_points={"datasette": ["secret_santa = datasette_secret_santa"]},
    install_requires=["datasette", "cryptography"],
    extras_require={"test": ["pytest", "pytest-asyncio"]},
    package_data={"datasette_secret_santa": ["static/*", "templates/*", "words.txt"]},
    python_requires=">=3.7",
)
