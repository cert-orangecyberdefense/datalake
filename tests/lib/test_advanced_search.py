import pytest
import responses
from datalake import Datalake
from tests.common.fixture import datalake

query_body = {
    "AND": [
        {
            "AND": [
                {
                    "field": "atom_type",
                    "multi_values": [
                        "phone_number"
                    ],
                    "type": "filter"
                },
                {
                    "field": "risk",
                    "range": {
                        "gt": 90
                    },
                    "type": "filter"
                }
            ]
        }
    ]
}
query_hash = "8697fbe09069e882e2de169ad480c2bf"


def mock_api_resp():
    responses.add(
        responses.POST,
        "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/advanced-queries/threats/",
        status=200,
        json={
            "count": 1,
            "href_query": "https://ti.extranet.mrti-center.com/api/v2/mrti/advanced-queries/threats/de70393f1c250ae675'\
            '66ec37c2032d1b/",
            "query_body": query_body,
            "query_hash": "8697fbe09069e882e2de169ad480c2bf",
            "results": []
        }
    )
    responses.add(
        responses.GET,
        'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/advanced-queries/threats'
        '/8697fbe09069e882e2de169ad480c2bf/?limit=0&offset=0', 
        status=200,
        json={
            "count": 1,
            "href_query": "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/advanced-queries/threats"
                          "/8697fbe09069e882e2de169ad480c2bf/66ec37c2032d1b/", 
            "query_body": query_body,
            "query_hash": "8697fbe09069e882e2de169ad480c2bf",
            "results": []
        }
    )
    responses.add(
        responses.GET,
        'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/advanced-queries/threats'
        '/8697fbe09069e882e2de169ad480c2bf/?limit=0&offset=0&ordering=first_seen',
        status=200,
        json={
            "count": 1,
            "href_query": "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/advanced-queries/threats"
                          "/8697fbe09069e882e2de169ad480c2bf/66ec37c2032d1b/",
            "query_body": query_body,
            "query_hash": "8697fbe09069e882e2de169ad480c2bf",
            "results": []
        }
    )


@responses.activate
def test_advanced_search_from_query_body(datalake: Datalake):
    mock_api_resp()
    resp = datalake.AdvancedSearch.advanced_search_from_query_body(query_body, limit=0)
    assert resp['query_hash'] == query_hash


@responses.activate
def test_advanced_search_from_query_hash(datalake: Datalake):
    mock_api_resp()
    resp = datalake.AdvancedSearch.advanced_search_from_query_hash(query_hash, limit=0)
    assert resp['query_hash'] == query_hash


def test_advanced_search_from_query_body_no_body(datalake: Datalake):
    with pytest.raises(ValueError) as exec_error:
        datalake.AdvancedSearch.advanced_search_from_query_body({}, limit=0)
    assert str(exec_error.value) == "query_body is required"


def test_advanced_search_from_query_hash_no_hash(datalake: Datalake):
    with pytest.raises(ValueError) as exec_error:
        datalake.AdvancedSearch.advanced_search_from_query_hash('', limit=0)
    assert str(exec_error.value) == "query_hash is required"


def test_advanced_search_from_query_hash_bad_ordering(datalake: Datalake):
    with pytest.raises(ValueError) as exec_error:
        datalake.AdvancedSearch.advanced_search_from_query_hash(query_hash, limit=0, ordering='badbad')
    assert str(exec_error.value) == "ordering needs to be one of the following str : first_seen, -first-seen, " \
                                    "last_updated, -last_updated, events_count, -events_count, sources_count, " \
                                    "-sources_count"


@responses.activate
def test_advanced_search_from_query_hash_ok_ordering(datalake: Datalake):
    mock_api_resp()
    resp = datalake.AdvancedSearch.advanced_search_from_query_hash(query_hash, limit=0, ordering='first_seen')
    assert resp['query_hash'] == query_hash
