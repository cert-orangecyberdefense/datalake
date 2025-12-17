import json
import pytest
import responses

from unittest.mock import patch

from datalake import Datalake
from datalake.common.config import Config
from datalake.common.token_manager import TokenManager

with open("tests/common/tests_endpoints.json", "r") as json_file:
    TEST_CONFIG_FILE = json.load(json_file)


class TestData:
    TEST_ENV = "prod"
    TEST_CONFIG = {
        "main": {
            TEST_ENV: TEST_CONFIG_FILE["main"][TEST_ENV],
            "preprod": TEST_CONFIG_FILE["main"]["preprod"],
        },
        "endpoints": TEST_CONFIG_FILE["endpoints"],
        "api_version": TEST_CONFIG_FILE["api_version"],
    }


@pytest.fixture
@responses.activate
def token_manager():
    url = (
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["token"]
    )
    auth_response = {"access_token": "access_token", "refresh_token": "refresh_token"}
    responses.add(responses.POST, url, json=auth_response, status=200)
    return TokenManager(
        TestData.TEST_CONFIG,
        environment=TestData.TEST_ENV,
        username="username",
        password="password",
    )


@pytest.fixture
@responses.activate
def datalake():
    # Path to the test-specific config file
    test_config_path = "tests/common/tests_endpoints.json"

    # Patch the _CONFIG_ENDPOINTS attribute of the Config class
    with patch.object(Config, "_CONFIG_ENDPOINTS", test_config_path):
        # Now when Config accesses _CONFIG_ENDPOINTS, it will use the test_config_path
        url = (
            TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
            + TestData.TEST_CONFIG["api_version"]
            + TestData.TEST_CONFIG["endpoints"]["token"]
        )

        auth_response = {"access_token": "12345", "refresh_token": "123456"}

        responses.add(responses.POST, url, json=auth_response, status=200)
        return Datalake(username="username", password="password", env=TestData.TEST_ENV)


@pytest.fixture
@responses.activate
def datalake_preprod():
    # Path to the test-specific config file
    test_config_path = "tests/common/tests_endpoints.json"

    # Patch the _CONFIG_ENDPOINTS attribute of the Config class
    with patch.object(Config, "_CONFIG_ENDPOINTS", test_config_path):
        # Now when Config accesses _CONFIG_ENDPOINTS, it will use the test_config_path
        url = (
            TestData.TEST_CONFIG["main"]["preprod"]
            + TestData.TEST_CONFIG["api_version"]
            + TestData.TEST_CONFIG["endpoints"]["token"]
        )

        auth_response = {"access_token": "12345", "refresh_token": "123456"}

        responses.add(responses.POST, url, json=auth_response, status=200)
        return Datalake(username="username", password="password", env="preprod")


@pytest.fixture
@responses.activate
def datalake_longterm_token():
    # Path to the test-specific config file
    test_config_path = "tests/common/tests_endpoints.json"

    # Patch the _CONFIG_ENDPOINTS attribute of the Config class
    with patch.object(Config, "_CONFIG_ENDPOINTS", test_config_path):
        # Now when Config accesses _CONFIG_ENDPOINTS, it will use the test_config_path
        return Datalake(longterm_token="longterm_token1234", env=TestData.TEST_ENV)
