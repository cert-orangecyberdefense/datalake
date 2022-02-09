"""
This is all common functions for basics scripts
"""
import argparse
import logging
import os
from typing import Tuple

from datalake.common.config import Config
from datalake.common.logger import configure_logging, logger
from datalake.common.token_manager import TokenManager

FOLDER_ABSOLUTE_PATH = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))


class BaseScripts:

    @staticmethod
    def start(description: str, output_file_required: bool = False) -> argparse.ArgumentParser:
        """
        Create a common parser for all the scripts. 
            Parser will contain: 
                --output,  name of the output file
                --env,     name of the environment of scripting
                --debug, if set, will show debug text
                --verbose, if set, will show information text
        """

        parser = argparse.ArgumentParser(
            description=description,
        )
        parser.add_argument(
            '-o',
            '--output',
            help='Output FILE path from script',
            required=output_file_required,
        )
        parser.add_argument(
            '-e',
            '--env',
            help='Execute on specified environment (Default: prod)',
            choices=['prod', 'preprod'],
            default='prod',
        )
        parser.add_argument(
            '--debug',
            help="Enable ",
            action="store_const", dest="loglevel", const=logging.DEBUG,
            default=logging.INFO,
        )
        parser.add_argument(
            '-q',
            '--quiet',
            help='Silence the output to only show warnings/errors',
            action="store_const", dest="loglevel", const=logging.WARNING,
        )
        return parser

    def load_config(self, args, username=None, password=None) -> Tuple[dict, TokenManager]:
        """Load correct config and generate first tokens"""
        configure_logging(args.loglevel)
        endpoint_config = Config().load_config()
        token_manager = TokenManager(
            endpoint_config,
            username=username,
            password=password,
            environment=args.env,
        )
        try:
            token_manager.get_token()
        except ValueError:
            logger.error("Couldn't generate Tokens, please check the login/password provided")
            exit()
        return endpoint_config, token_manager
