"""
Token manager will manage tokens for the scripts.
"""
import json
import os
from getpass import getpass

import requests

from datalake_scripts.common.logger import logger


class TokenGenerator:
    """
    Use it to generate token access to the API
    """

    def __init__(self, url: str):
        self.url_token = url + '/v1/auth/token/'
        self.url_refresh = url + '/v1/auth/refresh-token/'

    def retrieve_token(self, data: dict, refresh_token: bool):
        """
        Generate a token from data, if the refresh_token is set to True,
        then it will refresh a token, else it will create a new token.

            Variable data is the refresh token in case of refresh_token.
            Variable data is the header in case of not refresh_token.

        :param data: dict
        :param refresh_token: bool
        :return dict
        """
        if refresh_token:
            raw_res = requests.post(url=self.url_refresh, headers=data)
        else:
            raw_res = requests.post(url=self.url_token, json=data)
        api_response = json.loads(raw_res.text)
        if 'access_token' in api_response.keys():
            return api_response

        logger.debug('ERROR :  Wrong requests, please refer to the API')

        logger.debug(f'for URL: {self.url_refresh if refresh_token else self.url_token}\n')
        logger.debug(raw_res.text)
        return

    def get_token(self):
        """
        Generate token from user input, with email and password
        """
        username = os.getenv('OCD_DTL_USERNAME') or input('Email: ')
        password = os.getenv('OCD_DTL_PASSWORD') or getpass()
        print()
        return self.retrieve_token({'email': username, 'password': password}, False)

    def refresh_token(self, refresh_token: str):
        """
        Refresh the current token
        :param refresh_token: str
        """
        logger.debug('Token will be refresh')
        return self.retrieve_token({'Authorization': refresh_token}, True)
