"""
The base engine is use to request the API to the correct endpoint, and generate the data to be saved by the script.
Extend this engine to give it more functionality.
"""
import json
import os
from json.decoder import JSONDecodeError
from typing import Union
from urllib.parse import urljoin

from requests import Response

from datalake.common.logger import logger
from datalake.common.token_manager import TokenManager
from datalake.endpoints import Endpoint
from datalake_scripts.common import suppress_insecure_request_warns


class InvalidHeader(Exception):
    pass


class BaseEngine:
    ACCEPTED_HEADERS = {
        'json': 'application/json',
        'csv': 'text/csv'
    }
    OCD_DTL_QUOTA_TIME = int(os.getenv('OCD_DTL_QUOTA_TIME', 1))
    OCD_DTL_REQUESTS_PER_QUOTA_TIME = int(os.getenv('OCD_DTL_REQUESTS_PER_QUOTA_TIME', 5))
    logger.debug(f'Throttle selected: {OCD_DTL_REQUESTS_PER_QUOTA_TIME} queries per {OCD_DTL_QUOTA_TIME}s')

    Json = Union[dict, list]  # json like object that can be a dict or root level array

    def __init__(self, endpoint_config: dict, environment: str, token_manager: TokenManager):
        self.endpoint_config = endpoint_config
        self.environment = environment
        self.requests_ssl_verify = suppress_insecure_request_warns(environment)
        self.url = self._build_url(endpoint_config, environment)
        self.token_manager = token_manager
        self.endpoint = Endpoint(endpoint_config, environment, token_manager)

    def datalake_requests(self, url: str, method: str, headers: dict, post_body: dict = None):
        """
        Wrapper around the new datalake_requests to keep compatibility with old scrips
        """
        try:
            response = self.endpoint.datalake_requests(url, method, headers, post_body)
        except ValueError:
            logger.error('Request failed: Will return nothing for this request')
            return {}
        if 'Content-Type' in response.headers and 'text/csv' in response.headers['Content-Type']:
            return response.text
        else:
            try:
                dict_response = self._load_response(response)
                return dict_response
            except JSONDecodeError:
                logger.error('Request unexpectedly returned non dict value. Retrying')

    @staticmethod
    def output_type2header(value):
        """
        this method gets the CLI input arg value and generate the header content-type
        :param value: value to header
        :return: returns content-type header or raise an exception if there isn't an associated content-type value
        """
        if value.lower() in BaseEngine.ACCEPTED_HEADERS:
            return BaseEngine.ACCEPTED_HEADERS[value.lower()]
        raise InvalidHeader(f'{value.lower()} is not a valid. Use some of {BaseEngine.ACCEPTED_HEADERS.keys()}')

    @staticmethod
    def _load_response(api_response: Response):
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

    def _build_url(self, endpoint_config: dict, environment: str):
        """To be implemented by each subclass"""
        raise NotImplemented()

    def _build_url_for_endpoint(self, endpoint_name):
        base_url = urljoin(self.endpoint_config['main'][self.environment], self.endpoint_config['api_version'])
        enpoints = self.endpoint_config['endpoints']
        return urljoin(base_url, enpoints[endpoint_name], allow_fragments=True)
