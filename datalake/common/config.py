import json
import os

from datalake.common.token_manager import TokenGenerator
from datalake_scripts import logger

FOLDER_ABSOLUTE_PATH = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))


class Config:

    _CONFIG_ENDPOINTS = os.path.join(FOLDER_ABSOLUTE_PATH, '..', 'config', 'endpoints.json')

    def load_config(self, *, env='prod', username=None, password=None):
        """
        Load correct config and generate first tokens

        :return (dict, str, list<str, str>)
        """
        endpoint_config = self._load_config_file(self._CONFIG_ENDPOINTS)
        main_url = endpoint_config['main'][env]
        token_generator = TokenGenerator(endpoint_config, environment=env)
        token_json = token_generator.get_token(username, password)
        if token_json:
            tokens = [f'Token {token_json["access_token"]}', f'Token {token_json["refresh_token"]}']
            return endpoint_config, main_url, tokens
        else:
            logger.error("Couldn't generate Tokens, please check the login/password provided")
            exit()

    @staticmethod
    def _load_config_file(file_name: str) -> dict:
        with open(file_name, 'r') as config:
            return json.load(config)
