import pytest
import json
import responses
from unittest import mock
from datalake import Datalake
from tests.common.fixture import TestData, datalake

query_body = {
    "AND": [
        {
            "AND": [
                {"field": "atom_type", "multi_values": ["ip"], "type": "filter"},
                {
                    "field": "risk",
                    "inner_params": {
                        "threat_types": [
                            "ddos",
                            "fraud",
                            "hack",
                            "leak",
                            "malware",
                            "phishing",
                            "scam",
                            "scan",
                            "spam",
                        ]
                    },
                    "range": {"gt": 10},
                    "type": "filter",
                },
                {
                    "atom_values_only": "False",
                    "field": "atom_details",
                    "inner_params": {"atom_detail_path": "ip_address"},
                    "multi_values": [
                        "0.0.0.0/16",
                        "1.1.1.1/16",
                    ],
                    "type": "search",
                },
            ]
        }
    ]
}
query_hash = "528f01bf39572d6c9026b0097117d863"

bs_user = {
    "email": "123@mail.com",
    "full_name": "firstname lastname",
    "id": 12,
    "organization": {"id": 47, "name": "my_org", "path_names": ["my_org"]},
}

bs_status_json = {
    "count": 1,
    "results": [
        {
            "bulk_search": {
                "advanced_query_hash": "528f01bf39572d6c9026b0097117d863",
                "query_fields": ["threat_hashkey", "atom_value"],
            },
            "bulk_search_hash": "9b35f62fe46ee8fe361787b0882ceda7",
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
            "uuid": "d9c00380-2784-4386-9bc3-aff35cfeeb41",
        }
    ],
}

bs_status_url = (
    TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
    + TestData.TEST_CONFIG["api_version"]
    + TestData.TEST_CONFIG["endpoints"]["bulk-search-tasks"]
)

bs_creation_url = (
    TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
    + TestData.TEST_CONFIG["api_version"]
    + TestData.TEST_CONFIG["endpoints"]["bulk-search"]
)

bs_creation_response = {
    "bulk_search_hash": "9b35f62fe46ee8fe361787b0882ceda7",
    "query_fields": ["threat_hashkey", "atom_value"],
    "query_hash": "de70393f1c250ae67566ec37c2032d1b",
    "task_uuid": "f3212b05-a22f-470b-8e51-e875adf02d1e",
}

bs_result_json = {
    "advanced_query_hash": "528f01bf39572d6c9026b0097117d863",
    "bulk_search_hash": "9b35f62fe46ee8fe361787b0882ceda7",
    "results": [
        ["0.0.10.240", "eff1572f48d3118eb4aa23d63aa5f58b"],
        ["0.0.10.45", "ca24f9dc63198ecc0572a29f4deaaa54"],
        ["0.0.10.244", "7c678c25e5c5a05952dea784934f880b"],
    ],
}

expected_threats_diff = {
    "from": "2023-11-14 13:49:35",
    "to": "2023-11-15 12:05:10",
    "added": {
        ("0.0.10.244", "7c678c25e5c5a05952dea784934f880b"),
        ("0.0.10.45", "ca24f9dc63198ecc0572a29f4deaaa54"),
    },
    "removed": {("0.0.10.40", "ca24f9dc63198ecc0572a29f4deaaa54")},
}


def test_search_watch_no_body_no_query_hash(datalake: Datalake):
    with pytest.raises(ValueError) as exec_error:
        datalake.SearchWatch.search_watch()
    assert str(exec_error.value) == "Either a query_body or query_hash is required"


def test_search_watch_with_body_and_with_query_hash(datalake: Datalake):
    with pytest.raises(ValueError) as exec_error:
        datalake.SearchWatch.search_watch(query_body=query_body, query_hash=query_hash)
    assert str(exec_error.value) == "Either a query_body or query_hash is required"


@responses.activate
def test_search_watch_query_body_without_reference_file(datalake: Datalake):
    def bs_creation_callback(request):
        assert json.loads(request.body) == {
            "query_fields": ["atom_value", "threat_hashkey"],
            "query_body": query_body,
        }
        headers = {}
        return 200, headers, json.dumps(bs_creation_response)

    responses.add_callback(
        responses.POST,
        bs_creation_url,
        callback=bs_creation_callback,
        content_type="application/json",
    )

    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)

    with mock.patch(
        "datalake.miscellaneous.search_watch.save_output",
        side_effect=lambda *args, **kwargs: None,
    ):
        with mock.patch("datalake.BulkSearchTask.download_sync") as mock_download_sync:
            mock_download_sync.return_value = bs_result_json
            diff_threats = datalake.SearchWatch.search_watch(
                query_body=query_body, output_folder="tests/input_files"
            )
            assert diff_threats["added"] == expected_threats_diff["added"]
            assert diff_threats["removed"] == expected_threats_diff["removed"]


@responses.activate
def test_search_watch_query_body_with_reference_file(datalake: Datalake):
    def bs_creation_callback(request):
        assert json.loads(request.body) == {
            "query_fields": ["atom_value", "threat_hashkey"],
            "query_body": query_body,
        }
        headers = {}
        return 200, headers, json.dumps(bs_creation_response)

    responses.add_callback(
        responses.POST,
        bs_creation_url,
        callback=bs_creation_callback,
        content_type="application/json",
    )

    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)

    with mock.patch(
        "datalake.miscellaneous.search_watch.save_output",
        side_effect=lambda *args, **kwargs: None,
    ):
        with mock.patch("datalake.BulkSearchTask.download_sync") as mock_download_sync:
            mock_download_sync.return_value = bs_result_json
            diff_threats = datalake.SearchWatch.search_watch(
                query_body=query_body,
                output_folder="tests/input_files",
                reference_file="tests/input_files/528f01bf39572d6c9026b0097117d863-1699966175.json",
            )

            assert diff_threats["added"] == expected_threats_diff["added"]
            assert diff_threats["removed"] == expected_threats_diff["removed"]


@responses.activate
def test_search_watch_query_hash_with_reference_file(datalake: Datalake):
    def bs_creation_callback(request):
        assert json.loads(request.body) == {
            "query_fields": ["atom_value", "threat_hashkey"],
            "query_hash": query_hash,
        }
        headers = {}
        return 200, headers, json.dumps(bs_creation_response)

    responses.add_callback(
        responses.POST,
        bs_creation_url,
        callback=bs_creation_callback,
        content_type="application/json",
    )

    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)

    with mock.patch(
        "datalake.miscellaneous.search_watch.save_output",
        side_effect=lambda *args, **kwargs: None,
    ):
        with mock.patch("datalake.BulkSearchTask.download_sync") as mock_download_sync:
            mock_download_sync.return_value = bs_result_json
            diff_threats = datalake.SearchWatch.search_watch(
                query_hash=query_hash,
                output_folder="tests/input_files",
                reference_file="tests/input_files/528f01bf39572d6c9026b0097117d863-1699966175.json",
            )

            assert diff_threats["added"] == expected_threats_diff["added"]
            assert diff_threats["removed"] == expected_threats_diff["removed"]


@responses.activate
def test_search_watch_query_body_with_wrong_reference_file(datalake: Datalake):
    def bs_creation_callback(request):
        assert json.loads(request.body) == {
            "query_fields": ["atom_value", "threat_hashkey"],
            "query_body": query_body,
        }
        headers = {}
        return 200, headers, json.dumps(bs_creation_response)

    responses.add_callback(
        responses.POST,
        bs_creation_url,
        callback=bs_creation_callback,
        content_type="application/json",
    )

    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)

    with mock.patch(
        "datalake.miscellaneous.search_watch.save_output",
        side_effect=lambda *args, **kwargs: None,
    ):
        with mock.patch("datalake.BulkSearchTask.download_sync") as mock_download_sync:
            mock_download_sync.return_value = bs_result_json

            with pytest.raises(FileNotFoundError) as e:
                datalake.SearchWatch.search_watch(
                    query_body=query_body,
                    output_folder="tests/input_files",
                    reference_file="tests/528f01bf39572d6c9026b0097117d863-1699966175.json",
                )

            assert (
                "Reference file not found: tests/528f01bf39572d6c9026b0097117d863-1699966175.json"
                in str(e.value)
            )


@responses.activate
def test_search_watch_query_body_with_no_output_folder_and_no_reference_file(
    datalake: Datalake,
):
    def bs_creation_callback(request):
        assert json.loads(request.body) == {
            "query_fields": ["atom_value", "threat_hashkey"],
            "query_body": query_body,
        }
        headers = {}
        return 200, headers, json.dumps(bs_creation_response)

    responses.add_callback(
        responses.POST,
        bs_creation_url,
        callback=bs_creation_callback,
        content_type="application/json",
    )

    responses.add(responses.POST, bs_status_url, json=bs_status_json, status=200)

    with mock.patch(
        "datalake.miscellaneous.search_watch.save_output",
        side_effect=lambda *args, **kwargs: None,
    ):
        with mock.patch("datalake.BulkSearchTask.download_sync") as mock_download_sync:
            mock_download_sync.return_value = bs_result_json
            diff_threats = datalake.SearchWatch.search_watch(query_body=query_body)
            assert diff_threats == {}
