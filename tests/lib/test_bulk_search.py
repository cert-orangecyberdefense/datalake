import copy
import json

import responses
from datalake import Datalake, BulkSearchTaskState, BulkSearchTask
import pytest

from tests.common.fixture import datalake  # noqa needed fixture import

bs_user = {
    "email": "123@mail.com",
    "full_name": "firstname lastname",
    "id": 12,
    "organization": {
        "id": 47,
        "name": "my_org",
        "path_names": [
            "my_org"
        ]
    }
}

# <editor-fold desc="bs_status_json">
bs_status_json = {
    "count": 1,
    "results": [
        {
            "bulk_search": {
                "advanced_query_hash": "de70393f1c250ae67566ec37c2032d1b",
                "query_fields": [
                    "threat_hashkey",
                    "atom_value"
                ]
            },
            "bulk_search_hash": "ff2d2dc27f17f115d85647dced7a3106",
            "created_at": "2021-09-21T14:19:26.872073+00:00",
            "eta": None,
            "file_delete_after": "2021-09-24T14:20:01.661882+00:00",
            "file_deleted": False,
            "file_size": 61398,
            "finished_at": "2021-09-21T14:20:01.661882+00:00",
            "progress": 100,
            "queue_position": None,
            "results": 1172,
            "started_at": "2021-09-21T14:19:58.040840+00:00",
            "state": "DONE",
            "user": bs_user,
            "uuid": "d9c00380-2784-4386-9bc3-aff35cfeeb41"
        }
    ]
}
# </editor-fold>


@pytest.fixture
def bs_status_response():
    with responses.RequestsMock() as rsps:
        bs_status_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
        rsps.add(responses.POST, bs_status_url, json=bs_status_json, status=200)
        yield rsps


@pytest.fixture
def bulk_search_task(datalake: Datalake, bs_status_response):
    bs_creation_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/'
    bs_creation_response = {
        "bulk_search_hash": "ff2d2dc27f17f115d85647dced7a3106",
        "query_fields": [
            "threat_hashkey",
            "atom_value"
        ],
        "query_hash": "de70393f1c250ae67566ec37c2032d1b",
        "task_uuid": "d9c00380-2784-4386-9bc3-aff35cfeeb41"
    }
    bs_status_response.add(responses.POST, bs_creation_url, json=bs_creation_response, status=200)

    return datalake.BulkSearch.create_bulk_search_task(query_hash="123")


@responses.activate
def test_bulk_search_no_parameter(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.BulkSearch.create_bulk_search_task()
    assert str(err.value) == "Either a query_body or query_hash is required"


def test_bulk_search_query_hash(datalake: Datalake, bs_status_response):
    bs_creation_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/'
    bs_creation_response = {
        "bulk_search_hash": "ff2d2dc27f17f115d85647dced7a3106",
        "query_fields": [
            "threat_hashkey",
            "atom_value"
        ],
        "query_hash": "de70393f1c250ae67566ec37c2032d1b",
        "task_uuid": "d9c00380-2784-4386-9bc3-aff35cfeeb41"
    }
    bs_status_response.add(responses.POST, bs_creation_url, json=bs_creation_response, status=200)

    bs = datalake.BulkSearch.create_bulk_search_task(query_hash="123")
    assert bs.bulk_search_hash == 'ff2d2dc27f17f115d85647dced7a3106'
    assert bs.advanced_query_hash == 'de70393f1c250ae67566ec37c2032d1b'  # flatten field
    assert bs.query_fields == ["threat_hashkey", "atom_value"]  # flatten field
    assert bs.uuid == 'd9c00380-2784-4386-9bc3-aff35cfeeb41'
    assert bs.state == BulkSearchTaskState.DONE
    assert bs.user == bs_user  # field is not flatten as of now


def test_bulk_search_query_body(datalake: Datalake, bs_status_response):
    bs_creation_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/'
    bs_creation_response = {
        "bulk_search_hash": "ff2d2dc27f17f115d85647dced7a3106",
        "query_fields": [
            "threat_hashkey",
            "atom_value"
        ],
        "query_hash": "de70393f1c250ae67566ec37c2032d1b",
        "task_uuid": "d9c00380-2784-4386-9bc3-aff35cfeeb41"
    }
    bs_query_body = {
        "AND": [{
            "AND": [{
                "field": "metadata",
                "type": "search",
                "value": "some value"
            }]
        }]
    }

    def bs_creation_callback(request):
        assert json.loads(request.body) == {
            "query_fields": ["atom detail 1", "atom detail 2"],
            "query_body": bs_query_body,
        }
        headers = {}
        return 200, headers, json.dumps(bs_creation_response)

    bs_status_response.add_callback(
        responses.POST,
        bs_creation_url,
        callback=bs_creation_callback,
        content_type='application/json',
    )

    bs = datalake.BulkSearch.create_bulk_search_task(
        query_body=bs_query_body,
        query_fields=["atom detail 1", "atom detail 2"],
    )
    assert bs.bulk_search_hash == 'ff2d2dc27f17f115d85647dced7a3106'
    assert bs.uuid == 'd9c00380-2784-4386-9bc3-aff35cfeeb41'


@responses.activate
def test_bulk_search_task_update(bulk_search_task: BulkSearchTask):
    assert bulk_search_task.queue_position is None
    assert bulk_search_task.state == BulkSearchTaskState.DONE
    bs_status_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
    bs_update_json = copy.deepcopy(bs_status_json)
    bs_update_json['results'][0]['queue_position'] = 42
    responses.add(responses.POST, bs_status_url, json=bs_update_json, status=200)

    bulk_search_task.update()

    assert bulk_search_task.queue_position is 42
    assert bulk_search_task.state == BulkSearchTaskState.DONE  # field not modified
