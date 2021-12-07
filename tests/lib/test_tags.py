import pytest
import responses
from datalake import Datalake
from tests.common.fixture import datalake  # noqa needed fixture import

value_error_msg = "Tags has to be a list of string"



@responses.activate
def test_add_to_threat(datalake: Datalake):
    mock_api_resp()
    resp = datalake.Tags.add_to_threat(hashkey="123456abcd", tags=['tag'])
    assert resp[0]['author']['full_name'] == "string"


def test_add_to_threat_bad_tags(datalake: Datalake):
    with pytest.raises(ValueError) as execinfo:
        datalake.Tags.add_to_threat(hashkey="123456abcd", tags='[tag]')
    assert str(execinfo.value) == value_error_msg


def test_add_to_threat_empty_str(datalake: Datalake):
    with pytest.raises(ValueError) as execinfo:
        datalake.Tags.add_to_threat(hashkey="123456abcd", tags=[""])
    assert str(execinfo.value) == value_error_msg


def test_add_to_threat_empty_tags(datalake: Datalake):
    with pytest.raises(ValueError) as execinfo:
        datalake.Tags.add_to_threat(hashkey="123456abcd", tags=[])
    assert str(execinfo.value) == value_error_msg


def test_add_to_threat_not_str_tags(datalake: Datalake):
    with pytest.raises(ValueError) as execinfo:
        datalake.Tags.add_to_threat(hashkey="123456abcd", tags=[1, 2, 3, 4, 5])
    assert str(execinfo.value) == value_error_msg


@responses.activate
def test_add_to_threat_bad_hash(datalake: Datalake):
    mock_api_resp_404()
    with pytest.raises(ValueError) as execinfo:
        datalake.Tags.add_to_threat(hashkey="789101112efghij", tags=['tag'])
    assert str(execinfo.value) == '404: {"message": "Threat does not exist."}'


def mock_api_resp():
    responses.add(
        responses.POST,
        "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/123456abcd/tags/",
        status=200,
        json=[
            {
                "author": {
                    "full_name": "string",
                    "organization_id": 0,
                    "user_id": 0
                },
                "name": "string",
                "system_origin": {
                    "source": {
                        "source_id": "string",
                        "source_uses": [
                            "string"
                        ]
                    }
                },
                "timestamp_created": "2021-11-24T12:48:13.940Z",
                "visibility": "organization"
            }
        ]
    )


def mock_api_resp_404():
    responses.add(
        responses.POST,
        "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/789101112efghij/tags/",
        status=404,
        json={
            "message": "Threat does not exist."
        }
    )
