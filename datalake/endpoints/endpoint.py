"""
Base class used by all endpoints to request the API
"""
import json
import os
from urllib.parse import urljoin

import requests
from requests import Response

from datalake.common.ouput import Output
from datalake.common.logger import logger
from datalake.common.throttler import throttle
from datalake.common.token_manager import TokenManager


class Endpoint:
    OCD_DTL_QUOTA_TIME = int(os.getenv('OCD_DTL_QUOTA_TIME', 1))
    OCD_DTL_REQUESTS_PER_QUOTA_TIME = int(os.getenv('OCD_DTL_REQUESTS_PER_QUOTA_TIME', 5))
    logger.debug(f'Throttle selected: {OCD_DTL_REQUESTS_PER_QUOTA_TIME} queries per {OCD_DTL_QUOTA_TIME}s')

    SET_MAX_RETRY = 3

    def __init__(self, endpoint_config: dict, environment: str, token_manager: TokenManager):
        self.endpoint_config = endpoint_config
        self.environment = environment
        self.terminal_size = self._get_terminal_size()
        self.token_manager = token_manager
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
    def datalake_requests(
            self,
            url: str,
            method: str,
            headers: dict,
            post_body: dict = None,
    ) -> Response:
        """
        Use it to request the API
        """
        tries_left = self.SET_MAX_RETRY

        while tries_left > 0:
            headers['Authorization'] = self.token_manager.access_token
            logger.debug(self._pretty_debug_request(url, method, post_body, headers))

            response = self._send_request(url, method, headers, post_body)

            logger.debug(f'API response:\n{str(response.text)}')
            if response.status_code == 401:
                logger.warning('Token expired or Missing authorization header. Updating token')
                self.token_manager.process_auth_error(response.json().get('messages'))
            elif response.status_code == 422:
                logger.warning('Bad authorization header. Updating token')
                logger.debug(f'422 HTTP code: {response.text}')
                self.token_manager.process_auth_error(response.json().get('messages'))
            elif response.status_code < 200 or response.status_code > 299:
                logger.error(
                    f'API returned non 2xx response code : {response.status_code}\n{response.text}\n Retrying'
                )
            else:
                return response
            tries_left -= 1
        logger.error('Request failed')
        raise ValueError(f'{response.status_code}: {response.text.strip()}')

    @staticmethod
    def _post_headers(output=Output.JSON) -> dict:
        """headers for POST endpoints"""
        return {'Accept': output.value, 'Content-Type': 'application/json'}

    @staticmethod
    def _get_headers(output=Output.JSON) -> dict:
        """headers for GET endpoints"""
        return {'Accept': output.value}

    @staticmethod
    def _send_request(url: str, method: str, headers: dict, data: dict) -> Response:
        """
        Send the correct http request to url from method [get, post, delete, patch, put].
        Raise a TypeError 'Unknown method to requests {method}' when the method is not one of the above.
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

    def _pretty_debug_request(self, url: str, method: str, data: dict, headers: dict):
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
