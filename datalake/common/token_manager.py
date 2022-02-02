"""
Token manager will manage tokens for the scripts.
"""
import json
import os
from getpass import getpass
from urllib.parse import urljoin

import requests

from datalake.common.logger import logger


class TokenManager:
    """
    Use it to generate token access to the API
    """

    def __init__(self, endpoint_config: dict, *, environment: str, username=None, password=None):
        """environment can be either prod or preprod"""
        base_url = urljoin(endpoint_config['main'][environment], endpoint_config['api_version'])
        endpoints = endpoint_config['endpoints']

        self.url_token = urljoin(base_url, endpoints['token'], allow_fragments=True)
        self.url_refresh = urljoin(base_url, endpoints['refresh_token'], allow_fragments=True)

        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.get_token()

    def get_token(self):
        """
        Generate token from user input, with email and password
        """
        self.username = self.username or os.getenv('OCD_DTL_USERNAME') or input('Email: ')
        self.password = self.password or os.getenv('OCD_DTL_PASSWORD') or getpass()
        print()
        data = {'email': self.username, 'password': self.password}

        response = requests.post(url=self.url_token, json=data)
        json_response = json.loads(response.text)
        try:
            self.access_token = f'Token {json_response["access_token"]}'
            self.refresh_token = f'Token {json_response["refresh_token"]}'
        except KeyError:
            logger.error(f'An error occurred while retrieving an access token, for URL: {self.url_token}\n'
                         f'response of the API: {response.text}')
            raise ValueError(f'Could not login: {response.text}')

    def fetch_new_token(self):
        logger.debug('Token will be refreshed')
        headers = {'Authorization': self.refresh_token}
        response = requests.post(url=self.url_refresh, headers=headers)

        json_response = response.json()
        if response.status_code == 401 and json_response.get('messages') == 'Token has expired':
            logger.debug('Refreshing the refresh token')
            # Refresh token is also expired, we need to restart the authentication from scratch
            self.get_token()
        elif 'access_token' in json_response:
            self.access_token = f'Token {json_response["access_token"]}'
        else:  # an error occurred
            logger.error(f'An error occurred while refreshing the refresh token, for URL: {self.url_refresh}\n'
                         f'response of the API: {response.text}')
            raise ValueError(f'Could not refresh the token: {response.text}')

    def process_auth_error(self, error_msg: str):
        """
        Allow to update token when API response is either Missing Authorization Header or Token has expired.
        """
        if error_msg in (
                'Missing Authorization Header',
                'Bad Authorization header. Expected value \'Token <JWT>\''
        ):
            self.get_token()
        elif error_msg == 'Token has expired':
            self.fetch_new_token()
        else:
            raise ValueError(f'Unexpected msg: {error_msg}')
