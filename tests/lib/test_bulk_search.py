import asyncio
import copy
import datetime
import json
from http.client import ResponseNotReady

import pytest
import responses

from datalake import Datalake, BulkSearchTaskState, BulkSearchTask, Output, BulkSearchFailedError, BulkSearchNotFound
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
def bulk_search_task(datalake: Datalake):
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
    with responses.RequestsMock() as response_context:
        response_context.add(responses.POST, bs_creation_url, json=bs_creation_response, status=200)
        bs_status_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
        response_context.add(responses.POST, bs_status_url, json=bs_status_json, status=200)
        task = datalake.BulkSearch.create_task(query_hash="123")
    return task


@responses.activate
def test_bulk_search_no_parameter(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.BulkSearch.create_task()
    assert str(err.value) == "Either a query_body or query_hash is required"


@responses.activate
def test_bulk_search_query_hash(datalake: Datalake):
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
    responses.add(responses.POST, bs_creation_url, json=bs_creation_response, status=200)
    bs_status_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)

    bs = datalake.BulkSearch.create_task(query_hash="123")
    assert bs.bulk_search_hash == 'ff2d2dc27f17f115d85647dced7a3106'
    assert bs.advanced_query_hash == 'de70393f1c250ae67566ec37c2032d1b'  # flatten field
    assert bs.query_fields == ["threat_hashkey", "atom_value"]  # flatten field
    assert bs.uuid == 'd9c00380-2784-4386-9bc3-aff35cfeeb41'
    assert bs.state == BulkSearchTaskState.DONE
    assert bs.user == bs_user  # field is not flatten as of now
    assert bs.created_at == datetime.datetime(2021, 9, 21, 14, 19, 26, 872073)
    assert bs.eta is None  # Some timestamps are empty


@responses.activate
def test_bulk_search_query_body(datalake: Datalake):
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

    responses.add_callback(
        responses.POST,
        bs_creation_url,
        callback=bs_creation_callback,
        content_type='application/json',
    )
    bs_status_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)

    bs = datalake.BulkSearch.create_task(
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


@responses.activate
def test_bulk_search_task_not_found(datalake: Datalake):
    bs_status_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
    responses.add(responses.POST, bs_status_url, json={'results': []}, status=200)

    with pytest.raises(BulkSearchNotFound):
        datalake.BulkSearch.get_task('non existing task_uuid')


@responses.activate
def test_bulk_search_task_download(bulk_search_task: BulkSearchTask):
    task_uuid = bulk_search_task.uuid
    bs_download_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/task/{task_uuid}/'
    expected_result = "bulk search download"
    responses.add(responses.GET, bs_download_url, json=expected_result, status=200)

    download_result = bulk_search_task.download()

    assert download_result == expected_result


@responses.activate
def test_bulk_search_task_download_not_ready(bulk_search_task: BulkSearchTask):
    task_uuid = bulk_search_task.uuid
    bs_download_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/task/{task_uuid}/'
    error_message = "Not ready yet"
    json_returned = {"message": ("%s" % error_message)}
    responses.add(responses.GET, bs_download_url, json=json_returned, status=202)

    with pytest.raises(ResponseNotReady) as err:
        bulk_search_task.download()
    assert str(err.value) == error_message


@responses.activate
def test_bulk_search_task_download_invalid_output(bulk_search_task: BulkSearchTask):
    with pytest.raises(ValueError) as err:
        bulk_search_task.download(Output.MISP)
    assert str(err.value) == f'MISP output type is not supported. Outputs supported are: CSV, CSV_ZIP, JSON, JSON_ZIP,'\
                             ' STIX, STIX_ZIP'


@responses.activate
def test_bulk_search_task_download_zip_json_output(bulk_search_task: BulkSearchTask):
    task_uuid = bulk_search_task.uuid
    bs_download_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/task/{task_uuid}/'
    expected_result = 'zip json'

    def bs_download_callback(request):
        assert request.headers['Accept'] == 'application/zip'
        headers = {'Content-Type': 'application/zip'}
        return 200, headers, expected_result

    responses.add_callback(
        responses.GET,
        bs_download_url,
        callback=bs_download_callback,
        content_type='application/zip',
    )

    download_result = bulk_search_task.download(Output.JSON_ZIP)

    assert download_result == expected_result


@responses.activate
def test_bulk_search_task_download_async(bulk_search_task: BulkSearchTask):
    task_uuid = bulk_search_task.uuid
    bs_download_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/task/{task_uuid}/'
    expected_result = "bulk search download"
    responses.add(responses.GET, bs_download_url, json=expected_result, status=200)

    loop = asyncio.get_event_loop()
    download_result = loop.run_until_complete(bulk_search_task.download_async())

    assert download_result == expected_result


@responses.activate
def test_bulk_search_task_download_sync(bulk_search_task: BulkSearchTask):
    bs_status_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)
    bulk_search_task.state = BulkSearchTaskState.IN_PROGRESS  # download is not ready yet
    task_uuid = bulk_search_task.uuid
    bs_download_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/task/{task_uuid}/'
    expected_result = "bulk search download"
    responses.add(responses.GET, bs_download_url, json=expected_result, status=200)

    download_result = bulk_search_task.download_sync()

    assert download_result == expected_result


@pytest.mark.asyncio
async def test_bulk_search_task_download_async_timeout(bulk_search_task: BulkSearchTask):
    with responses.RequestsMock() as response_context:  # pytest.mark.asyncio is not compatible with responses decorator
        bulk_search_task.state = BulkSearchTaskState.IN_PROGRESS  # download will never be ready
        bs_update_json = copy.deepcopy(bs_status_json)
        bs_update_json['results'][0]['state'] = 'IN_PROGRESS'
        bs_status_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
        response_context.add(responses.POST, bs_status_url, json=bs_update_json, status=200)

        loop = asyncio.get_event_loop()
        task = loop.create_task(bulk_search_task.download_async(timeout=0.2))
        with pytest.raises(TimeoutError):
            await task


@responses.activate
def test_bulk_search_task_download_sync_timeout(bulk_search_task: BulkSearchTask):
    bulk_search_task.state = BulkSearchTaskState.IN_PROGRESS  # download will never be ready
    bs_update_json = copy.deepcopy(bs_status_json)
    bs_update_json['results'][0]['state'] = 'IN_PROGRESS'
    bs_status_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
    responses.add(responses.POST, bs_status_url, json=bs_update_json, status=200)

    with pytest.raises(TimeoutError):
        bulk_search_task.download_sync(timeout=0.2)


@responses.activate
def test_bulk_search_task_download_sync_failed(bulk_search_task: BulkSearchTask):
    bulk_search_task.state = BulkSearchTaskState.IN_PROGRESS
    bs_update_json = copy.deepcopy(bs_status_json)
    bs_update_json['results'][0]['state'] = 'CANCELLED'
    bs_status_url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-search/tasks/'
    responses.add(responses.POST, bs_status_url, json=bs_update_json, status=200)

    with pytest.raises(BulkSearchFailedError) as err:
        bulk_search_task.download_sync()
    assert err.value.failed_state == BulkSearchTaskState.CANCELLED
