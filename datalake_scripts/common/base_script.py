"""
This is all common functions for basics scripts
"""

import argparse
import logging
import os

FOLDER_ABSOLUTE_PATH = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))


class InvalidHeader(Exception):
    pass


class BaseScripts:
    ACCEPTED_HEADERS = {"json": "application/json", "csv": "text/csv"}

    @staticmethod
    def start(
        description: str, output_file_required: bool = False
    ) -> argparse.ArgumentParser:
        """
        Create a common parser for all the scripts.
            Parser will contain:
                -o/--output,  name of the output file
                -e/--env,     name of the environment of scripting
                -D/--debug, if set, will show debug messages
                -q/--quiet, if set, will only show warning and error messages
        """

        parser = argparse.ArgumentParser(
            description=description,
        )
        parser.add_argument(
            "-o",
            "--output",
            help="output file path from script",
            required=output_file_required,
        )
        parser.add_argument(
            "-e",
            "--env",
            help="execute on specified environment, default value is prod.",
            choices=["prod", "preprod"],
            default="prod",
        )
        parser.add_argument(
            "-D",
            "--debug",
            help="enable debug logs, default log level is info",
            action="store_const",
            dest="loglevel",
            const=logging.DEBUG,
            default=logging.INFO,
        )
        parser.add_argument(
            "-q",
            "--quiet",
            help="silence the output to only show warnings/errors, default log level is info",
            action="store_const",
            dest="loglevel",
            const=logging.WARNING,
            default=logging.INFO,
        )
        return parser

    @staticmethod
    def output_type2header(value):
        """
        this method gets the CLI input arg value and generate the header content-type
        :param value: value to header
        :return: returns content-type header or raise an exception if there isn't an associated content-type value
        """
        if value.lower() in BaseScripts.ACCEPTED_HEADERS:
            return BaseScripts.ACCEPTED_HEADERS[value.lower()]
        raise InvalidHeader(
            f"{value.lower()} is not a valid. Use some of {BaseScripts.ACCEPTED_HEADERS.keys()}"
        )
