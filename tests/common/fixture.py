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
            "token": "auth/token/",
            "refresh-token": "auth/refresh-token/",
            "advanced-queries-threats": "mrti/advanced-queries/threats/",
            "advanced-queries-threats-query-hash": "mrti/advanced-queries/threats/{query_hash}/",
            "atom-values": "mrti/atom-values/",
            "bulk-search": "mrti/bulk-search/",
            "bulk-search-tasks": "mrti/bulk-search/tasks/",
            "bulk-search-task": "mrti/bulk-search/task/{task_uuid}/",
            "bulk-manual-threats": "mrti/bulk-manual-threats/",
            "bulk-manual-threats-task": "mrti/bulk-manual-threats/task/{task_uuid}/",
            "sources": "mrti/sources/",
            "tag-subcategory-filtered": "mrti/tag-subcategory/filtered/",
            "threats-manual": "mrti/threats-manual/",
            "threats-bulk-lookup": "mrti/threats/bulk-lookup/",
            "threats": "mrti/threats/{hashkey}/",
            "threats-lookup": "mrti/threats/lookup/",
            "threats-comments": "mrti/threats/{hashkey}/comments/",
            "threats-tags": "mrti/threats/{hashkey}/tags/",
            "threats-atom-values-extract": "mrti/threats/atom-values-extract/",
            "threats-bulk-scoring-edits": "mrti/threats/bulk-scoring-edits/",
            "threats-sighting": "mrti/threats/sighting/",
            "threats-sighting-file": "mrti/threats/sighting-file/{hashkey}/",
            "threats-sighting-filtered": "mrti/threats/sighting/filtered/",
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
