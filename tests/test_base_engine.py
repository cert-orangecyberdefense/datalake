import pytest
from parser import ParserError
from datalake_scripts.common.base_engine import BaseEngine


@pytest.mark.parametrize('value, expected', [
    ('json', 'application/json'),
    ('csv', 'text/csv')
])
def test_output_type2header(value, expected):
    assert BaseEngine.output_type2header(value) == expected


def test_output_type2header_parser_error():
    bad_header = 'foo'
    with pytest.raises(ParserError) as e:
        BaseEngine.output_type2header(bad_header)
    assert str(e.value) == f'{bad_header} is not a valid. Use some of {BaseEngine.ACCEPTED_HEADERS.keys()}'
