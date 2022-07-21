import json
import logging

import pytest
import responses

from datalake import Datalake, AtomType
from tests.common.fixture import datalake  # noqa needed fixture import


@responses.activate
def test_token_auth(datalake):
    expected_tokens = {
        'access_token': '12345',
        'refresh_token': '123456',
    }

    token_manager = datalake.Threats.token_manager

    assert token_manager.access_token == f"Token {expected_tokens['access_token']}"
    assert token_manager.refresh_token == f"Token {expected_tokens['refresh_token']}"


@responses.activate
def test_invalid_credentials(caplog):
    url = 'https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/'

    api_error_msg = 'Wrong credentials provided'
    api_response = {'message': api_error_msg}
    responses.add(responses.POST, url, json=api_response, status=401)
    with caplog.at_level(logging.ERROR):
        with pytest.raises(ValueError) as ve:
            Datalake(username='username@wow.com', password='password')
    assert str(ve.value) == f'Could not login: {{"message": "{api_error_msg}"}}'
    assert caplog.messages == [
        f'An error occurred while retrieving an access token, for URL: {url}\n'
        f'response of the API: {{"message": "{api_error_msg}"}}'
    ]


@responses.activate
def test_access_token_expired(datalake, caplog):
    expected_json = {'wow.com': 'bad'}

    def lookup_callback(request):
        headers = {}
        if request.headers['Authorization'] == 'Token 12345':
            return 401, headers, json.dumps({'msg': 'Token has expired'})
        elif request.headers['Authorization'] == 'Token refreshed_token':
            return 200, headers, json.dumps(expected_json)
        else:
            raise Exception()

    responses.add_callback(
        responses.GET,
        'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/lookup/',
        callback=lookup_callback,
        content_type='application/json',
    )

    def refresh_token_callback(request):
        headers = {}
        assert request.headers['Authorization'] == 'Token 123456', 'token passed is not the refresh token'
        return 200, headers, json.dumps({'access_token': 'refreshed_token'})

    responses.add_callback(
        responses.POST,
        'https://datalake.cert.orangecyberdefense.com/api/v2/auth/refresh-token/',
        callback=refresh_token_callback,
        content_type='application/json',
    )

    assert datalake.Threats.lookup(atom_value='wow.com', atom_type=AtomType.DOMAIN) == expected_json
    assert caplog.messages == ['Token expired or Missing authorization header. Updating token']


@responses.activate
def test_invalid_token(datalake, caplog):
    expected_json = {'wow.com': 'bad'}
    invalid_access_token = '12345'

    def lookup_callback(request):
        headers = {}
        if request.headers['Authorization'] == invalid_access_token:
            return 401, headers, json.dumps(
                {'msg': "Missing 'Token' type in 'Authorization' header. Expected 'Authorization: Token <JWT>'"}
            )
        elif request.headers['Authorization'] == 'Token valid_token':
            return 200, headers, json.dumps(expected_json)
        else:
            raise Exception()

    responses.add_callback(
        responses.GET,
        'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/lookup/',
        callback=lookup_callback,
        content_type='application/json',
    )

    def token_callback(request):
        return 200, {}, json.dumps({'access_token': 'valid_token', 'refresh_token': ''})

    responses.add_callback(
        responses.POST,
        'https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/',
        callback=token_callback,
        content_type='application/json',
    )

    datalake.Threats.token_manager.access_token = invalid_access_token

    assert datalake.Threats.lookup(atom_value='wow.com', atom_type=AtomType.DOMAIN) == expected_json
    assert caplog.messages == ['Token expired or Missing authorization header. Updating token']
