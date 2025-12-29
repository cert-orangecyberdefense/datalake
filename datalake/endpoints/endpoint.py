"""
Base class used by all endpoints to request the API
"""

import json
import logging
import os
from urllib.parse import urljoin

import requests
from requests import Response
from requests.adapters import HTTPAdapter, Retry

from datalake.common.output import Output
from datalake.common.throttler import throttle
from datalake.common.token_manager import TokenManager
from datalake.common.utils import get_error_message

OCD_DTL_QUOTA_TIME = int(os.getenv("OCD_DTL_QUOTA_TIME", 1))
OCD_DTL_REQUESTS_PER_QUOTA_TIME = int(os.getenv("OCD_DTL_REQUESTS_PER_QUOTA_TIME", 5))
OCD_DTL_MAX_RETRIES = int(os.getenv("OCD_DTL_MAX_RETRIES", 3))


class Endpoint:

    def __init__(
        self,
        logger,
        endpoint_config: dict,
        environment: str,
        token_manager: TokenManager,
        proxies: dict = None,
        verify: bool = True,
    ):
        self.logger = logger
        self.logger.debug(
            f"Throttle selected: {OCD_DTL_REQUESTS_PER_QUOTA_TIME} queries per {OCD_DTL_QUOTA_TIME}s"
        )
        self.endpoint_config = endpoint_config
        self.environment = environment
        self.terminal_size = self._get_terminal_size()
        self.token_manager = token_manager
        self.proxies = proxies
        self.verify = verify
        self.session = requests.Session()

        # Configure HTTP retry policy
        retry_policy = Retry(
            total=OCD_DTL_MAX_RETRIES,  # Number of retries
            backoff_factor=1,  # How much time between retries (exponential)
            raise_on_status=False,  # Raise an error when the number of retries is exhausted
            status_forcelist=[
                429,
                500,
                502,
                503,
                504,
            ],  # Retry for those HTTP status codes
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retry_policy))
        self.session.mount("https://", HTTPAdapter(max_retries=retry_policy))

    def _get_terminal_size(self) -> int:
        """Return the terminal size for pretty print"""
        try:
            terminal_size = os.get_terminal_size()
            if len(terminal_size) == 2:
                return int(terminal_size[1])
        except OSError:
            self.logger.debug(
                "Couldn't get terminal size, falling back to 80 char wide"
            )
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
        stream=False,
    ) -> Response:
        """
        Use it to request the API
        """

        self.logger.debug(self._pretty_debug_request(url, method, post_body, headers))

        response = None
        retry_auth_count = OCD_DTL_MAX_RETRIES
        if OCD_DTL_MAX_RETRIES < 1:
            retry_auth_count = 1
        while retry_auth_count >= 0:
            headers["Authorization"] = (
                self.token_manager.access_token or self.token_manager.longterm_token
            )

            response = self._send_request(
                self,
                url=url,
                method=method,
                headers=headers,
                data=post_body,
                stream=stream,
                proxies=self.proxies,
                verify=self.verify,
            )

            if self.logger.isEnabledFor(logging.DEBUG):
                # Don't compute response.text var if not needed, especially for streaming response
                self.logger.debug("API response:\n%s", response.text)
            if response.status_code == 401:
                self.logger.warning(
                    "Missing authorization header or Token Error. Updating token"
                )
                self.token_manager.process_auth_error(response.json())
            else:
                break
            retry_auth_count -= 1

        if response.status_code == 422:
            json_resp = response.json()
            try:
                error_msg = get_error_message(json_resp)
            except ValueError:
                error_msg = response.text
            raise ValueError(f"422 HTTP code: {error_msg}")
        elif response.status_code < 200 or response.status_code > 299:
            self.logger.error(
                f"API returned non 2xx response code : {response.status_code}\n{response.text}"
            )
        else:
            return response
        self.logger.error("Request failed")
        raise ValueError(f"{response.status_code}: {response.text.strip()}")

    @staticmethod
    def _post_headers(output=Output.JSON) -> dict:
        """headers for POST endpoints"""
        return {"Accept": output.value, "Content-Type": "application/json"}

    @staticmethod
    def _get_headers(output=Output.JSON) -> dict:
        """headers for GET endpoints"""
        return {"Accept": output.value}

    @staticmethod
    def _send_request(
        self,
        url: str,
        method: str,
        headers: dict,
        data: dict,
        stream=False,
        proxies: dict = None,
        verify: bool = True,
    ) -> Response:
        """
        Send the correct http request to url from method [get, post, delete, patch, put].
        Raise a TypeError 'Unknown method to requests {method}' when the method is not one of the above.
        """
        common_kwargs = {
            "url": url,
            "headers": headers,
            "stream": stream,
            "verify": verify,
        }
        if proxies:
            common_kwargs["proxies"] = proxies

        if method == "get":
            api_response = self.session.get(**common_kwargs)
        elif method == "post":
            api_response = self.session.post(**common_kwargs, data=json.dumps(data))
        elif method == "delete":
            api_response = self.session.delete(**common_kwargs, data=json.dumps(data))
        elif method == "patch":
            api_response = self.session.patch(**common_kwargs, data=json.dumps(data))
        elif method == "put":
            api_response = self.session.put(**common_kwargs, data=json.dumps(data))
        else:
            self.logger.debug(
                "ERROR : Wrong requests, please only do [get, post, put, patch, delete] method"
            )
            raise TypeError("Unknown method to requests %s", method)
        return api_response

    def _pretty_debug_request(self, url: str, method: str, data: dict, headers: dict):
        debug = (
            "-" * self.terminal_size
            + "DEBUG - datalake_requests:\n"
            + f" - url: \n{url}\n"
            + f" - method: \n{method}\n"
            + f" - headers: \n{headers}\n"
            + f" - data: \n{data}\n"
            + f" - token: \n{self.token_manager.access_token}\n"
            + f" - refresh_token: \n{self.token_manager.refresh_token}\n"
            + f" - longterm_token: \n{self.token_manager.longterm_token}\n"
            + "-" * self.terminal_size
        )
        return debug

    def _build_url_for_endpoint(self, endpoint_name, **kwargs):
        base_url = urljoin(
            self.endpoint_config["main"][self.environment],
            self.endpoint_config["api_version"],
        )
        endpoints = self.endpoint_config["endpoints"]
        return urljoin(base_url, endpoints[endpoint_name], allow_fragments=True)
