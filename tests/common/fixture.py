import pytest
import responses

from datalake import Datalake
from datalake.common.token_manager import TokenManager


class TestData:
    TEST_ENV = 'my_env'
    TEST_CONFIG = {
        'main': {
            TEST_ENV: 'https://datalake.com/api/'
        },
        'endpoints': {
            'bulk-search': 'mrti/bulk-search/',
            'threats': 'mrti/threats/',
            'threats-manual': 'mrti/threats-manual/',
            'token': 'auth/token/',
            'advanced-search': 'mrti/advanced-queries/threats/',
            'advanced-search-hash': 'mrti/advanced-queries/threats/{query_hash}/?limit={limit}&offset={offset}&ordering'\
            '={ordering}',
            'refresh_token': 'auth/refresh-token/',
            'lookup': 'mrti/threats/lookup/',
            'comment': 'mrti/threats/{hashkey}/comments/',
            'tag': 'mrti/threats/{hashkey}/tags/',
        },
        'api_version': 'v42/'
    }


@pytest.fixture
@responses.activate
def token_manager():
    url = 'https://datalake.com/api/v42/auth/token/'
    auth_response = {
        "access_token": "access_token",
        "refresh_token": "refresh_token"
    }
    responses.add(responses.POST, url, json=auth_response, status=200)
    return TokenManager(TestData.TEST_CONFIG, environment=TestData.TEST_ENV, username='username', password='password')


@pytest.fixture
@responses.activate
def datalake():
    url = 'https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/'

    auth_response = {
        "access_token": "12345",
        "refresh_token": "123456"
    }

    responses.add(responses.POST, url, json=auth_response, status=200)
    return Datalake(username='username', password='password')
