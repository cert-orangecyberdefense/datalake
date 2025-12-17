import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()


def read_version_or_cli_name(option: str):
    with open("datalake_scripts/cli.py") as f:
        for line in f:
            if option == "version" and line.strip().startswith("VERSION"):
                return line.split("=")[1].strip().strip('"')
            if option == "cli_name" and line.strip().startswith("CLI_NAME"):
                return line.split("=")[1].strip().strip('"')


CLI_NAME = read_version_or_cli_name("cli_name")
VERSION = read_version_or_cli_name("version")

setup(
    name="datalake_scripts",
    version=VERSION,
    author="OCD",
    author_email="cert-contact.ocd@orange.com",
    description="A collection of scripts to easily use the API of OCD Datalake",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/cert-orangecyberdefense/datalake/",
    package_dir={
        "": ".",
    },
    packages=find_packages(),
    install_requires=["requests", "halo", "prettytable"],
    test_suite="nose.collector",
    entry_points={
        "console_scripts": (f"{CLI_NAME} = datalake_scripts.cli:main",),
    },
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Topic :: Security",
        "Natural Language :: English",
    ],
    include_package_data=True,
    package_data={
        "datalake": ["config/endpoints.json"],
    },
    python_requires=">=3.6",
)
