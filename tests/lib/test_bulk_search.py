import responses
from datalake import Datalake
import pytest


@pytest.fixture
@responses.activate
def datalake():
    url = 'https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/'

    auth_response = {
        "access_token": "12345",
        "refresh_token": "123456"
    }

    responses.add(responses.POST, url,
                  json=auth_response, status=200)

    return Datalake(username='lesid', password='getget')
