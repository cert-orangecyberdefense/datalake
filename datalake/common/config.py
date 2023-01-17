import json
import os

FOLDER_ABSOLUTE_PATH = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))


class Config:

    _CONFIG_ENDPOINTS = os.path.join(FOLDER_ABSOLUTE_PATH, '..', 'config', 'endpoints.json')

    def load_config(self):
        """
        Load correct config and generate first tokens

        :return (dict, str, list<str, str>)
        """
        with open(self._CONFIG_ENDPOINTS, 'r') as config:
            return json.load(config)
