"""
Base class used by all endpoints to request the API
"""
import os
import json
import parser
import requests

from json.decoder import JSONDecodeError
from typing import Union
from urllib.parse import urljoin

from requests import Response

from datalake import Output
from datalake.common.logger import logger
from datalake.common.throttler import throttle
from datalake.common.token_manager import TokenManager


class Endpoint:
    ACCEPTED_HEADERS = {
        'json': 'application/json',
        'csv': 'text/csv'
    }
    OCD_DTL_QUOTA_TIME = int(os.getenv('OCD_DTL_QUOTA_TIME', 1))
    OCD_DTL_REQUESTS_PER_QUOTA_TIME = int(os.getenv('OCD_DTL_REQUESTS_PER_QUOTA_TIME', 5))
    logger.debug(f'Throttle selected: {OCD_DTL_REQUESTS_PER_QUOTA_TIME} queries per {OCD_DTL_QUOTA_TIME}s')

    Json = Union[dict, list]  # json like object that can be a dict or root level array

    SET_MAX_RETRY = 3

    def __init__(self, endpoint_config: dict, environment: str, token_manager: TokenManager):
        self.endpoint_config = endpoint_config
        self.environment = environment
        self.terminal_size = self._get_terminal_size()
        self.token_manager = token_manager
        self.headers = None
        self.SET_MAX_RETRY = 3

    @staticmethod
    def _get_terminal_size() -> int:
        """Return the terminal size for pretty print"""
        try:
            terminal_size = os.get_terminal_size()
            if len(terminal_size) == 2:
                return int(terminal_size[1])
        except OSError:
            logger.debug("Couldn't get terminal size, falling back to 80 char wide")
        return 80

    @throttle(
        period=OCD_DTL_QUOTA_TIME,
        call_per_period=OCD_DTL_REQUESTS_PER_QUOTA_TIME,
    )
    def datalake_requests(self, url: str, method: str, headers: dict, post_body: dict = None):
        """
        Use it to request the API
        """
        self.headers = headers
        tries_left = self.SET_MAX_RETRY

        logger.debug(self._pretty_debug_request(url, method, post_body, headers))

        if not headers.get('Authorization'):
            fresh_tokens = self.token_generator.get_token()
            self.replace_tokens(fresh_tokens)
        while True:
            response = self._send_request(url, method, headers, post_body)
            logger.debug(f'API response:\n{str(response.text)}')
            if response.status_code == 401:
                logger.warning('Token expired or Missing authorization header. Updating token')
                self._token_update(self._load_response(response))
            elif response.status_code == 422:
                logger.warning('Bad authorization header. Updating token')
                logger.debug(f'422 HTTP code: {response.text}')
                self._token_update(self._load_response(response))
            elif response.status_code < 200 or response.status_code > 299:
                logger.error(f'API returned non 2xx response code : {response.status_code}\n{response.text}'
                             f'\n Retrying')
            elif 'Content-Type' in response.headers and 'text/csv' in response.headers['Content-Type']:
                return response.text
            else:
                try:
                    dict_response = self._load_response(response)
                    return dict_response
                except JSONDecodeError:
                    logger.error('Request unexpectedly returned non dict value. Retrying')
            tries_left -= 1
            if tries_left <= 0:
                logger.error('Request failed: Will return nothing for this request')
                return {}
            # time.sleep(5)

    @staticmethod
    def output_type2header(value):
        """
        this method gets the CLI input arg value and generate the header content-type
        :param value: value to header
        :return: returns content-type header or raise an exception if there isn't an associated content-type value
        """
        if value.lower() in Endpoint.ACCEPTED_HEADERS:
            return Endpoint.ACCEPTED_HEADERS[value.lower()]

        raise parser.ParserError(f'{value.lower()} is not a valid. Use some of {Endpoint.ACCEPTED_HEADERS.keys()}')

    def _post_headers(self, output=Output.JSON) -> dict:
        """headers for POST endpoints"""
        json_ = 'application/json'
        return {'Authorization': self.token_manager.access_token, 'Accept': output.value, 'Content-Type': json_}

    def _get_headers(self, output=Output.JSON) -> dict:
        """headers for GET endpoints"""
        return {'Authorization': self.token_manager.access_token, 'Accept': output.value}

    def _send_request(self, url: str, method: str, headers: dict, data: dict):
        """
        Send the correct http request to url from method [get, post, delete, patch, put].
        Raise a TypeError 'Unknown method to requests {method}' when the method is not one of the above.

        :param url: str
        :param method: str
        :param data: dict
        :param headers: dict
        :param tokens: list
        :return: str
        """
        common_kwargs = {
            'url': url,
            'headers': headers,
        }

        if method == 'get':
            api_response = requests.get(**common_kwargs)
        elif method == 'post':
            api_response = requests.post(**common_kwargs, data=json.dumps(data))
        elif method == 'delete':
            api_response = requests.delete(**common_kwargs, data=json.dumps(data))
        elif method == 'patch':
            api_response = requests.patch(**common_kwargs, data=json.dumps(data))
        elif method == 'put':
            api_response = requests.put(**common_kwargs, data=json.dumps(data))
        else:
            logger.debug('ERROR : Wrong requests, please only do [get, post, put, patch, delete] method')
            raise TypeError('Unknown method to requests %s', method)
        return api_response

    def _load_response(self, api_response: Response):
        """
        Load the API response from JSON format to dict.
        The endpoint for events is a bit special, the json.loads() doesn't work for the return format of the API.
        We get for this special case a return dict containing the length of the response i.e.:

            if length of response ==  3 then: no events

        :param: api_response: dict
        :return: dict_response
        """
        if api_response.text.startswith('[') and api_response.text.endswith(']\n'):
            # This condition is for the date-histogram endpoints
            dict_response = {'response_length': len(api_response.text)}
        else:
            dict_response = json.loads(api_response.text)
        return dict_response

    def _token_update(self, dict_response: dict):
        """
        Allow to update token when API response is either Missing Authorization Header
        or Token has expired. Return False is the token has been regenerated.

        :param dict_response: dict
        :return: Bool
        """
        if dict_response.get('msg') == 'Missing Authorization Header':
            fresh_tokens = self.token_generator.get_token()
            self.replace_tokens(fresh_tokens)
            return False
        elif dict_response.get('msg') == 'Bad Authorization header. Expected value \'Token <JWT>\'':
            fresh_tokens = self.token_generator.get_token()
            self.replace_tokens(fresh_tokens)
            return False
        elif dict_response.get('msg') == 'Token has expired':
            fresh_tokens = self.token_generator.refresh_token(self.tokens[1])
            self.replace_tokens(fresh_tokens)
            return False

        return True

    def replace_tokens(self, fresh_tokens: dict):
        access_token = fresh_tokens["access_token"]
        # Update of the refresh token is optional
        refresh_token = fresh_tokens.get('refresh_token', self.tokens[1].replace('Token ', ''))

        self.tokens = [f'Token {access_token}', f'Token {refresh_token}']
        self.headers['Authorization'] = self.tokens[0]

    def _pretty_debug_request(self, url: str, method: str, data: dict, headers: dict):
        """
        Return pretty debug string

        :param url: str
        :param method: str
        :param data: dict
        :param headers: dict
        :param tokens: list
        :return: str
        """
        debug = ('-' * self.terminal_size +
                 'DEBUG - datalake_requests:\n' +
                 f' - url: \n{url}\n' +
                 f' - method: \n{method}\n' +
                 f' - headers: \n{headers}\n' +
                 f' - data: \n{data}\n' +
                 f' - token: \n{self.token_manager.access_token}\n' +
                 f' - refresh_token: \n{self.token_manager.refresh_token}\n' +
                 '-' * self.terminal_size)
        return debug

    def _build_url_for_endpoint(self, endpoint_name):
        base_url = urljoin(self.endpoint_config['main'][self.environment], self.endpoint_config['api_version'])
        enpoints = self.endpoint_config['endpoints']
        return urljoin(base_url, enpoints[endpoint_name], allow_fragments=True)
