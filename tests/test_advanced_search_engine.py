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


@pytest.mark.parametrize('query_body', [
    query_body_template,  # Query body as returned in the GUI
    {'AND': query_body_template},  # Full query body
])
@responses.activate
def test_split_list(tokens, query_body):
    def request_callback(request):
        payload = json.loads(request.body)
        resp_body = response_template
        resp_body['query_body'] = payload['query_body']
        headers = {}
        return 200, headers, json.dumps(resp_body)

    response_template = {
        'count': 2, 'query_body': {'AND': query_body},
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

    assert response['query_body']['AND'], 'query body must have a top level AND'
    assert response['query_body'] == {'AND': query_body_template}, 'query body must be full'
    assert response['query_hash'] == 'de70393f1c250ae67566ec37c2032d1b'
