import pytest
from datalake_scripts.common.base_engine import BaseEngine


@pytest.mark.parametrize('value, expected', [
    ('json', 'application/json'),
    ('csv', 'text/csv'),
    ('foo', None)
])
def test_output_type2header(value, expected):
    assert BaseEngine.output_type2header(value) == expected
