import pytest
from datalake_scripts.common.base_script import InvalidHeader, BaseScripts


@pytest.mark.parametrize(
    "value, expected", [("json", "application/json"), ("csv", "text/csv")]
)
def test_output_type2header(value, expected):
    assert BaseScripts.output_type2header(value) == expected


def test_output_type2header_parser_error():
    bad_header = "foo"
    with pytest.raises(InvalidHeader) as e:
        BaseScripts.output_type2header(bad_header)
    assert (
        str(e.value)
        == f"{bad_header} is not a valid. Use some of {BaseScripts.ACCEPTED_HEADERS.keys()}"
    )
