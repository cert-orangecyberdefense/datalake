"""
This is all common functions for basics scripts
"""
import argparse
import csv
import json
import logging
import os
from typing import List

from datalake_scripts.common.logger import configure_logging, logger
from datalake_scripts.common.token_manager import TokenGenerator

FOLDER_ABSOLUTE_PATH = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))


class BaseScripts:

    _CONFIG_ENDPOINTS = os.path.join(FOLDER_ABSOLUTE_PATH, '..', 'config', 'endpoints.json')
    PACKAGE_NAME = 'ocd-dtl'

    def save_output(self, file_name: str, data):
        """
        Save the data in a file. 
        If data is dict, file format will be JSON.
        If data is a list, file format will be txt.
        Else it will be saved as it comes.
        """
        with open(file_name, 'w+') as file_to_write:
            if isinstance(data, dict):
                file_to_write.write(json.dumps(data, sort_keys=True, indent=2))
            elif isinstance(data, list):
                for item in data:
                    file_to_write.write(f'{item}\n')
            else:
                file_to_write.write(data)

    def start(self, description: str) -> argparse.ArgumentParser:
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

    def load_config(self, args):
        """
        Load correct config and generate first tokens

        :return (dict, str, list<str, str>)
        """
        configure_logging(args.loglevel)
        endpoint_url = self._load_json(self._CONFIG_ENDPOINTS)
        main_url = endpoint_url['main'][args.env]
        token_generator = TokenGenerator(main_url)
        token_json = token_generator.get_token()
        if token_json:
            tokens = [f'Token {token_json["access_token"]}', f'Token {token_json["refresh_token"]}']
            return endpoint_url, main_url, tokens
        else:
            logger.error("Couldn't generate Tokens, please check the login/password provided")
            exit()

    def _load_json(self, file_name: str) -> dict:
        """
        Load a Json file as a dict
        """
        with open(file_name, 'r') as config:
            payload = json.load(config)
        return payload

    def _load_list(self, file_name: str) -> list:
        """
        Load a file and retrieve each line in a list
        """
        return [line.rstrip('\n') for line in open(file_name)]

    def _load_csv(self, file_name: str, delimiter: str = ',', column: int = 0) -> List[str]:
        """
        Load a CSV file and return one column in a list
        """
        ret = []
        i = 0  # Keep current row number in case of exception
        try:
            with open(file_name, 'r') as csvfile:
                csv_reader = csv.reader(csvfile, delimiter=delimiter)
                for i, row in enumerate(csv_reader):
                    if row and not row[0].startswith('#'):  # We discard comments
                        ret.append(row[column])
        except IndexError:
            raise ValueError(f'Csv passed does not have enough columns on line {i} or the delimiter is incorrect')
        return ret
