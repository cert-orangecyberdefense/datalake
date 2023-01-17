from unittest.mock import create_autospec, Mock

import pytest
from requests import Response

from datalake import Output
from datalake.common.ouput import parse_response


@pytest.mark.parametrize(
    'method, content_type',
    [
        ('json', None),
        ('json', Output.JSON.value),
        ('json', Output.MISP.value),
        ('json', Output.STIX.value),
        ('text', Output.CSV.value),
        ('text', Output.JSON_ZIP.value),
        ('text', Output.CSV_ZIP.value),
    ]
)
def test_parse_response_default(method, content_type):
    mock: Mock = create_autospec(Response)
    mock.headers = {'Content-Type': content_type} if content_type else {}
    expected_res = 'json'
    if method == 'json':
        mock.json.return_value = expected_res
    elif method == 'text':
        mock.text = expected_res

    res = parse_response(mock)

    assert res == expected_res
