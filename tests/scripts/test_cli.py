import sys
import pytest
from unittest.mock import patch
from datalake_scripts.cli import Cli
from datalake_scripts.scripts import (
    add_threats,
    get_threats_by_hashkey,
    edit_score,
    get_threats_from_query_hash,
    add_comments,
    lookup_threats,
    add_tags,
    get_query_hash,
    bulk_lookup_threats,
    advanced_search,
    get_atom_values,
    get_filtered_tag_subcategory,
    search_watch,
)


# Tests to make sure the commands call the right scripts (and recognizes the command)
@pytest.mark.parametrize(
    "function_script",
    [
        add_threats,
        get_threats_by_hashkey,
        edit_score,
        get_threats_from_query_hash,
        add_comments,
        lookup_threats,
        add_tags,
        get_query_hash,
        bulk_lookup_threats,
        advanced_search,
        get_atom_values,
        get_filtered_tag_subcategory,
        search_watch,
    ],
)
def test_name_function(function_script):
    command_name = function_script.__name__.split(".")[-1]

    if command_name == "get_threats_by_hashkey":
        command_name = "get_threats"

    with patch.object(
        function_script, "main", return_value="mocked response"
    ) as mock_function_script:
        # Act: Change sys.argv to simulate the command line arguments
        with patch(
            "sys.argv",
            ["ocd-dtl", command_name, "--output", "output.txt", "--env", "preprod"],
        ):
            cli_app = Cli()

        # Assert: ensure the mock was called and the result is as expected
        mock_function_script.assert_called_once_with(
            ["--output", "output.txt", "--env", "preprod"]
        )
