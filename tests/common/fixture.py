import pytest
import responses

from datalake import Datalake


@pytest.fixture
def tokens():
    """Fake tokens to be used in mocked requests"""
    return ['access token', 'refresh token']


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
