import pytest
import responses

from unittest.mock import patch

from datalake import Datalake
from datalake.common.config import Config
from datalake.common.token_manager import TokenManager


class TestData:
    TEST_ENV = "prod"
    TEST_CONFIG = {
        "main": {
            TEST_ENV: "https://datalake.com/api/",
            "preprod": "https://ti.datalake.com/api/",
        },
        "endpoints": {
            "bulk-search": "mrti/bulk-search/",
            "bulk-search-task": "mrti/bulk-search/tasks/",
            "retrieve-bulk-search": "mrti/bulk-search/task/{task_uuid}/",
            "threats": "mrti/threats/",
            "advanced-search": "mrti/advanced-queries/threats/",
            "advanced-search-hash": "mrti/advanced-queries/threats/{query_hash}/",
            "threats-manual": "mrti/threats-manual/",
            "threats-bulk-lookup": "mrti/threats/bulk-lookup/",
            "threats-manual-bulk": "mrti/bulk-manual-threats/",
            "threats-atom-values": "mrti/atom-values/",
            "retrieve-threats-manual-bulk": "mrti/bulk-manual-threats/task/{task_uuid}/",
            "token": "auth/token/",
            "refresh_token": "auth/refresh-token/",
            "lookup": "mrti/threats/lookup/",
            "comment": "mrti/threats/{hashkey}/comments/",
            "tag": "mrti/threats/{hashkey}/tags/",
            "atom-values-extract": "mrti/threats/atom-values-extract/",
            "bulk-scoring-edits": "mrti/threats/bulk-scoring-edits/",
            "submit-sightings": "mrti/threats/sighting/",
            "sighting": "mrti/threats/sighting-file/{hashkey}/",
            "sighting-filtered": "mrti/threats/sighting/filtered/",
            "sources": "mrti/sources/",
            "filtered-tag-subcategory": "mrti/tag-subcategory/filtered/",
        },
        "api_version": "v42/",
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
