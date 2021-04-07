"""
Token manager will manage tokens for the scripts.
"""
import json
import os
from getpass import getpass
from urllib.parse import urljoin

import requests

from datalake_scripts.common import suppress_insecure_request_warns
from datalake_scripts.common.logger import logger


class TokenGenerator:
    """
    Use it to generate token access to the API
    """

    def __init__(self, endpoint_config: dict, *, environment: str):
        """environment can be either prod, dtl2 or preprod"""
        base_url = urljoin(endpoint_config['main'][environment], endpoint_config['api_version'])
        endpoints = endpoint_config['endpoints']

        self.requests_ssl_verify = suppress_insecure_request_warns(environment)
        self.url_token = urljoin(base_url, endpoints['token'], allow_fragments=True)
        self.url_refresh = urljoin(base_url, endpoints['refresh_token'], allow_fragments=True)

    def get_token(self):
        """
        Generate token from user input, with email and password
        """
        username = os.getenv('OCD_DTL_USERNAME') or input('Email: ')
        password = os.getenv('OCD_DTL_PASSWORD') or getpass()
        print()
        data = {'email': username, 'password': password}

        response = requests.post(url=self.url_token, json=data, verify=self.requests_ssl_verify)
        json_response = json.loads(response.text)
        if 'access_token' in json_response.keys():
            return json_response
        # else an error occurred

        logger.error(f'An error occurred while retrieving an access token, for URL: {self.url_token}\n'
                     f'response of the API: {response.text}')
        exit(1)

    def refresh_token(self, refresh_token: str):
        """
        Refresh the current token
        :param refresh_token: str
        """
        logger.debug('Token will be refresh')
        headers = {'Authorization': refresh_token}
        response = requests.post(url=self.url_refresh, headers=headers, verify=self.requests_ssl_verify)

        json_response = json.loads(response.text)
        if response.status_code == 401 and json_response.get('msg') == 'Token has expired':
            logger.debug('Refreshing the refresh token')
            # Refresh token is also expired, we need to restart the authentication from scratch
            return self.get_token()
        elif 'access_token' in json_response:
            return json_response
        # else an error occurred

        logger.error(f'An error occurred while refreshing the refresh token, for URL: {self.url_refresh}\n'
                     f'response of the API: {response.text}')
        exit(1)
