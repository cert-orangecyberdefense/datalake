import json

import pytest
import responses

from datalake_scripts import AdvancedSearch
from tests.test_endpoint_config import TEST_CONFIG, TEST_ENV
from fixture import tokens  # noqa needed fixture import

query_body_template = [
    {'field': 'atom_type', 'multi_values': ['phone_number'], 'type': 'filter'},
    {'field': 'risk', 'range': {'gt': 0}, 'type': 'filter'},
]


def make_advanced_search_request(query_body, tokens):
    def request_callback(request):
        payload = json.loads(request.body)
        resp_body = response_template
        resp_body['query_body'] = payload['query_body']
        headers = {}
        return 200, headers, json.dumps(resp_body)

    response_template = {
        'count': 2, 'query_body': query_body,
        'query_hash': 'de70393f1c250ae67566ec37c2032d1b',
        'href_query': 'https://datalake.com/api/v42/mrti/advanced-queries/threats/de70393f1c250ae67566ec37c2032d1b/',
        'results': []
    }

    responses.add_callback(
        responses.POST,
        'https://datalake.com/api/v42/mrti/advanced-queries/threats/',
        callback=request_callback,
        content_type='application/json',
    )

    advanced_search = AdvancedSearch(TEST_CONFIG, environment=TEST_ENV, tokens=tokens)
    response = advanced_search.get_threats(query_body=query_body, limit=0)
    return response


@responses.activate
def test_full_query_body_request(tokens):
    query_body = {'AND': [{'AND': query_body_template}]}  # Full query body
    response = make_advanced_search_request(query_body, tokens)

    assert response['query_body']['AND'], 'query body must have a top level AND'
    assert response['query_body'] == {'AND': [{'AND': query_body_template}]}, 'query body must be full'
    assert response['query_hash'] == 'de70393f1c250ae67566ec37c2032d1b'


@responses.activate
def test_minimal_query_body_no_longer_accepted(tokens):
    query_body = query_body_template  # Query body as previously returned in the GUI
    with pytest.raises(ValueError) as ve:
        make_advanced_search_request(query_body, tokens)
    assert str(ve.value) == 'Query body is not valid: top level "AND" is missing'
