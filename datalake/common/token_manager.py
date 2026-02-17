"""
Token manager will manage tokens for the scripts.
"""

import json
import os
from getpass import getpass
from urllib.parse import urljoin

import requests

from datalake.common.utils import get_error_message


class TokenManager:
    """
    Use it to generate token access to the API
    """

    def __init__(
        self,
        endpoint_config: dict,
        *,
        logger,
        environment: str,
        username=None,
        password=None,
        longterm_token=None,
        proxies: dict = None,
        verify: bool = True,
    ):
        """environment can be either prod or preprod"""
        base_url = urljoin(
            endpoint_config["main"][environment], endpoint_config["api_version"]
        )
        endpoints = endpoint_config["endpoints"]

        self.url_token = urljoin(base_url, endpoints["token"], allow_fragments=True)
        self.url_refresh = urljoin(
            base_url, endpoints["refresh-token"], allow_fragments=True
        )
        self.logger = logger
        self.username = username
        self.password = password
        self.longterm_token = longterm_token
        self.proxies = proxies
        self.verify = verify
        self.access_token = None
        self.refresh_token = None
        self.get_token()

    def get_token(self):
        """
        Generate token from user input
         by default, we use the values given as args,
         then in second choice, we try the environment variables,
         and finally we ask for user input
         Priority is given to the long term token if it is provided at the same place (args, environment variable or prompt) than the username/password )
        """
        if self.username is None and self.password is None:
            """We do not ignore the values username and password in favor of long term token if the two credentials are given explicitly when instancing Datalake"""
            self.longterm_token = self.longterm_token or os.getenv(
                "OCD_DTL_LONGTERM_TOKEN"
            )
            self.logger.debug("Using Long Term Token")

        self.username = self.username or os.getenv("OCD_DTL_USERNAME")
        self.password = self.password or os.getenv("OCD_DTL_PASSWORD")

        if self.longterm_token is None and (
            self.username is None or self.password is None
        ):
            """I only ask in prompt if no other choice"""
            self.username = self.username or input("Email: ")
            self.password = self.password or getpass()
            self.longterm_token = self.longterm_token or input(
                "Long term token (Default : None): "
            )
            print()

        if self.longterm_token:
            self.longterm_token = f"Token {self.longterm_token}"
            if self.username or self.password:
                self.logger.warning(
                    f"Using provided Long Term Token for Authentication to the Datalake API. Ignoring username and/or password."
                )
        else:
            data = {"email": self.username, "password": self.password}

            response = requests.post(
                url=self.url_token, json=data, proxies=self.proxies, verify=self.verify
            )
            json_response = json.loads(response.text)
            try:
                self.access_token = f'Token {json_response["access_token"]}'
                self.refresh_token = f'Token {json_response["refresh_token"]}'
            except KeyError:
                self.logger.error(
                    f"An error occurred while retrieving an access token, for URL: {self.url_token}\n"
                    f"response of the API: {response.text}"
                )
                raise ValueError(f"Could not login: {response.text}")

    def fetch_new_token(self):
        self.logger.debug("Token will be refreshed")
        headers = {"Authorization": self.refresh_token}
        response = requests.post(
            url=self.url_refresh,
            headers=headers,
            proxies=self.proxies,
            verify=self.verify,
        )

        json_response = response.json()
        if (
            response.status_code == 401
            and get_error_message(json_response) == "Token has expired"
        ):
            self.logger.info("Refreshing the refresh token")
            # Refresh token is also expired, we need to restart the authentication from scratch
            self.get_token()
        elif "access_token" in json_response:
            self.access_token = f'Token {json_response["access_token"]}'
        else:  # an error occurred
            self.logger.error(
                f"An error occurred while refreshing the refresh token, for URL: {self.url_refresh}\n"
                f"response of the API: {response.text}"
            )
            raise ValueError(f"Could not refresh the token: {response.text}")

    def process_auth_error(self, json_resp: dict):
        """
        Allow to update token when API response is either Missing Authorization Header or Token has expired.
        """
        error_msg = get_error_message(json_resp)
        if error_msg in (
            "Missing Authorization Header",
            "Bad Authorization header. Expected value 'Token <JWT>'",
            "Missing 'Token' type in 'Authorization' header. Expected 'Authorization: Token <JWT>'",
        ):
            self.get_token()
        elif error_msg == "Token has expired":
            if self.longterm_token:
                raise ValueError(f"Long term token has expired")
            else:
                self.fetch_new_token()
        elif error_msg == "Token has been revoked":
            raise ValueError(f"Long term token has been revoked")
        elif error_msg == "Fresh token required":
            raise ValueError(
                f"You cannot use Long term token with this endpoint, please use only the credentials username and password to init the Datalake instance for this request"
            )
        elif (
            error_msg
            in ("Invalid token", "Not enough segments", "Signature verification failed")
            and self.longterm_token
        ):
            raise ValueError(f"Long term token is invalid")
        else:
            raise ValueError(f"Unexpected msg: {error_msg}")
