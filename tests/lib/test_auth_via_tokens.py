import json
import logging
from functools import partial

import pytest
import responses

from unittest.mock import patch
from datalake.common.config import Config

from datalake import Datalake, AtomType
from tests.common.fixture import (
    datalake,
    datalake_longterm_token,
    TestData,
)  # noqa needed fixture import


@responses.activate
def test_token_auth(datalake):
    expected_tokens = {
        "longterm_token": None,
        "access_token": "12345",
        "refresh_token": "123456",
    }

    token_manager = datalake.Threats.token_manager
    assert token_manager.url_token == (
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["token"]
    )
    assert token_manager.longterm_token == None
    assert token_manager.access_token == f"Token {expected_tokens['access_token']}"
    assert token_manager.refresh_token == f"Token {expected_tokens['refresh_token']}"


@responses.activate
def test_invalid_credentials(datalake, caplog):
    # Path to the test-specific config file
    test_config_path = "tests/common/tests_endpoints.json"

    # Patch the _CONFIG_ENDPOINTS attribute of the Config class
    with patch.object(Config, "_CONFIG_ENDPOINTS", test_config_path):
        url = (
            TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
            + TestData.TEST_CONFIG["api_version"]
            + TestData.TEST_CONFIG["endpoints"]["token"]
        )

        api_error_msg = "Wrong credentials provided"
        api_response = {"message": api_error_msg}
        responses.add(responses.POST, url, json=api_response, status=401)
        with caplog.at_level(logging.ERROR):
            with pytest.raises(ValueError) as ve:
                Datalake(username="username@wow.com", password="password")
        assert str(ve.value) == f'Could not login: {{"message": "{api_error_msg}"}}'
        assert caplog.messages == [
            f"An error occurred while retrieving an access token, for URL: {url}\n"
            f'response of the API: {{"message": "{api_error_msg}"}}'
        ]


def lookup_callback(
    request,
    expired_token,
    valid_token,
    response_on_valid_token,
    response_on_expired_token=None,
):
    headers = {}
    if not response_on_expired_token:
        response_on_expired_token = {"message": "Token has expired"}  # Default value
    if request.headers["Authorization"] == f"Token {expired_token}":
        return 401, headers, json.dumps(response_on_expired_token)
    elif request.headers["Authorization"] == f"Token {valid_token}":
        return 200, headers, json.dumps(response_on_valid_token)
    else:
        raise Exception()


@responses.activate
def test_access_token_expired(datalake, caplog):
    caplog.set_level(level=logging.INFO, logger="OCD_DTL")
    expected_json = {"wow.com": "bad"}

    responses.add_callback(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-lookup"],
        callback=partial(
            lookup_callback,
            expired_token="12345",
            valid_token="refreshed_token",
            response_on_valid_token=expected_json,
        ),
        content_type="application/json",
    )

    def refresh_token_callback(request):
        headers = {}
        assert (
            request.headers["Authorization"] == "Token 123456"
        ), "token passed is not the refresh token"
        return 200, headers, json.dumps({"access_token": "refreshed_token"})

    responses.add_callback(
        responses.POST,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["refresh-token"],
        callback=refresh_token_callback,
        content_type="application/json",
    )

    assert (
        datalake.Threats.lookup(atom_value="wow.com", atom_type=AtomType.DOMAIN)
        == expected_json
    )
    assert caplog.messages == [
        "Missing authorization header or Token Error. Updating token"
    ]


@responses.activate
def test_refresh_token_expired(datalake, caplog):
    caplog.set_level(level=logging.INFO, logger="OCD_DTL")
    expected_json = {"wow.com": "bad"}

    responses.add_callback(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-lookup"],
        callback=partial(
            lookup_callback,
            expired_token="12345",
            valid_token="new_token",
            response_on_valid_token=expected_json,
        ),
        content_type="application/json",
    )

    def refresh_token_callback(request):
        headers = {}
        assert (
            request.headers["Authorization"] == "Token 123456"
        ), "token passed is not the refresh token"
        return 401, headers, json.dumps({"message": "Token has expired"})

    responses.add_callback(
        responses.POST,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["refresh-token"],
        callback=refresh_token_callback,
        content_type="application/json",
    )
    responses.post(
        url=TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["token"],
        json={"access_token": "new_token", "refresh_token": ""},
        status=200,
    )

    assert (
        datalake.Threats.lookup(atom_value="wow.com", atom_type=AtomType.DOMAIN)
        == expected_json
    )
    assert caplog.messages == [
        "Missing authorization header or Token Error. Updating token",
        "Refreshing the refresh token",
    ]


@responses.activate
def test_invalid_token(datalake, caplog):
    expected_json = {"wow.com": "bad"}
    invalid_access_token = "not-valid-token"
    valid_access_token = "valid_token"

    responses.add_callback(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-lookup"],
        callback=partial(
            lookup_callback,
            expired_token=invalid_access_token,
            valid_token=valid_access_token,
            response_on_valid_token=expected_json,
            response_on_expired_token={
                "message": "Missing 'Token' type in 'Authorization' header. Expected 'Authorization: Token <JWT>'"
            },
        ),
        content_type="application/json",
    )

    responses.post(
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["token"],
        json={"access_token": valid_access_token, "refresh_token": ""},
        content_type="application/json",
    )

    datalake.Threats.token_manager.access_token = f"Token {invalid_access_token}"

    assert (
        datalake.Threats.lookup(atom_value="wow.com", atom_type=AtomType.DOMAIN)
        == expected_json
    )
    assert caplog.messages == [
        "Missing authorization header or Token Error. Updating token"
    ]


def test_active_longterm_token(datalake_longterm_token):
    token_manager = datalake_longterm_token.Threats.token_manager
    expected_tokens = {
        "longterm_token": "longterm_token1234",
        "access_token": None,
        "refresh_token": None,
    }

    assert token_manager.longterm_token == f"Token {expected_tokens['longterm_token']}"
    assert token_manager.access_token == None
    assert token_manager.refresh_token == None


def lookup_callback_longterm_token(
    request,
    expired_longterm_token,
    disabled_longterm_token,
    not_fresh_token,
    response_on_expired_longterm_token={"message": "Token has expired"},
    response_on_disabled_longterm_token={"message": "Token has been revoked"},
    response_on_not_fresh_token={"message": "Fresh token required"},
    response_on_invalid_token={"message": "Invalid token"},
):
    headers = {}
    if request.headers["Authorization"] == f"Token {expired_longterm_token}":
        return 401, headers, json.dumps(response_on_expired_longterm_token)
    elif request.headers["Authorization"] == f"Token {disabled_longterm_token}":
        return 401, headers, json.dumps(response_on_disabled_longterm_token)
    elif request.headers["Authorization"] == f"Token {not_fresh_token}":
        return 401, headers, json.dumps(response_on_not_fresh_token)
    else:
        return 401, headers, json.dumps(response_on_invalid_token)


@responses.activate
def test_disabled_longterm_token(datalake_longterm_token, caplog):
    caplog.set_level(level=logging.INFO, logger="OCD_DTL")

    responses.add_callback(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-lookup"],
        callback=partial(
            lookup_callback_longterm_token,
            expired_longterm_token="expired_longterm_token_1234",
            disabled_longterm_token="longterm_token1234",
            not_fresh_token="not_fresh_token_1234",
        ),
        content_type="application/json",
    )

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ValueError) as ve:
            r = datalake_longterm_token.Threats.lookup(
                atom_value="wow.com", atom_type=AtomType.DOMAIN
            )
    assert str(ve.value) == "Long term token has been revoked"
    assert caplog.messages == [
        "Missing authorization header or Token Error. Updating token"
    ]


@responses.activate
def test_expired_longterm_token(datalake_longterm_token, caplog):
    caplog.set_level(level=logging.INFO, logger="OCD_DTL")

    responses.add_callback(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-lookup"],
        callback=partial(
            lookup_callback_longterm_token,
            expired_longterm_token="longterm_token1234",
            disabled_longterm_token="disabled_token1234",
            not_fresh_token="not_fresh_token_1234",
        ),
        content_type="application/json",
    )

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ValueError) as ve:
            r = datalake_longterm_token.Threats.lookup(
                atom_value="wow.com", atom_type=AtomType.DOMAIN
            )
    assert str(ve.value) == "Long term token has expired"
    assert caplog.messages == [
        "Missing authorization header or Token Error. Updating token"
    ]


# test long test token on endpoint requiring fresh token
@responses.activate
def test_requires_fresh_token(datalake_longterm_token, caplog):
    caplog.set_level(level=logging.INFO, logger="OCD_DTL")

    responses.add_callback(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-lookup"],
        callback=partial(
            lookup_callback_longterm_token,
            expired_longterm_token="expired_longterm_token_1234",
            disabled_longterm_token="disabled_token1234",
            not_fresh_token="longterm_token1234",
        ),
        content_type="application/json",
    )

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ValueError) as ve:
            r = datalake_longterm_token.Threats.lookup(
                atom_value="wow.com", atom_type=AtomType.DOMAIN
            )
    assert (
        str(ve.value)
        == "You cannot use Long term token with this endpoint, please use only the credentials username and password to init the Datalake instance for this request"
    )
    assert caplog.messages == [
        "Missing authorization header or Token Error. Updating token"
    ]


@responses.activate
def test_invalid_longterm_token(datalake_longterm_token, caplog):
    caplog.set_level(level=logging.INFO, logger="OCD_DTL")

    responses.add_callback(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-lookup"],
        callback=partial(
            lookup_callback_longterm_token,
            expired_longterm_token="expired_longterm_token_1234",
            disabled_longterm_token="disabled_token1234",
            not_fresh_token="not_fresh_token_1234",
        ),
        content_type="application/json",
    )

    with caplog.at_level(logging.WARNING):
        with pytest.raises(ValueError) as ve:
            r = datalake_longterm_token.Threats.lookup(
                atom_value="wow.com", atom_type=AtomType.DOMAIN
            )
    assert str(ve.value) == "Long term token is invalid"
    assert caplog.messages == [
        "Missing authorization header or Token Error. Updating token"
    ]
