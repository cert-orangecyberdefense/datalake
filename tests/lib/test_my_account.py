import pytest
import responses
from datalake import Datalake
from tests.common.fixture import TestData, datalake

mock_results_data = {
    "email": "user@example.com",
    "first_name": "string",
    "force_password_change": True,
    "full_name": "string",
    "has_password": True,
    "id": 0,
    "is_active": True,
    "is_deleted": False,
    "last_login": "2025-10-15T08:43:33.390Z",
    "last_name": "string",
    "organization": {"id": 0, "name": "string", "path_names": ["string"]},
    "previous_login": "2025-10-15T08:43:33.390Z",
    "request_limit": 0,
    "role": {
        "administration_permissions": {"description": "string", "name": "string"},
        "id": 0,
        "name": "string",
    },
    "totp_enabled": True,
}


def mock_api_response():
    responses.add(
        responses.GET,
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["users-me"],
        json=mock_results_data,  # Only return the "results" part
        status=200,
    )


@responses.activate
def test_my_account(datalake: Datalake):
    mock_api_response()
    response = datalake.MyAccount.me()
    assert response == mock_results_data
    assert isinstance(response, dict), "Results should be a dict"
    assert responses.calls[0].request.url, (
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["users-me"]
    )
    assert responses.calls[0].request.method, "GET"
