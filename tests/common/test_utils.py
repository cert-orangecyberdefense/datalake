from datalake.common.utils import (
    join_dicts,
    check_normalized_timestamp,
    convert_date_to_normalized_timestamp,
)
from datalake_scripts.helper_scripts.utils import split_list


def test_split_list():
    list_to_split = [1, 2, 3, 4, 5]

    generator = split_list(list_to_split, 3)
    head = next(generator)
    tail = next(generator)

    assert head == [1, 2, 3]
    assert tail == [4, 5]


def test_join_dicts():
    d1 = {
        "k1": ["k1", "k2", "k3"],
        "a1": ["a1", "a2", "a3"],
        "b1": ["b1", "b2"],
    }
    d2 = {
        "k1": ["k4", "k5", "k6"],
        "a1": ["a4", "a5", "a6"],
    }
    d3 = {
        "k1": ["k7", "k8"],
        "a1": ["a7", "a8"],
        "p1": ["p1", "p2"],
    }

    assert join_dicts(d1, d2, d3) == {
        "k1": ["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"],
        "a1": ["a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8"],
        "b1": ["b1", "b2"],
        "p1": ["p1", "p2"],
    }


def test_normalized_timestamp():
    assert check_normalized_timestamp("2023-09-14T15:00:00.000Z") == True
    assert check_normalized_timestamp("2023-09-15T15:12:13.825Z") == True
    assert check_normalized_timestamp("2023-9-15T15:12:13.825Z") == False
    assert check_normalized_timestamp("2023-09-15T15:12:13.825321Z") == False
    assert check_normalized_timestamp("2023-09-15 15:12:13.825Z") == False
    assert check_normalized_timestamp("2023-09-10T15:12:13.825") == False


def test_convert_date_to_normalized_timestamp():
    assert (
        convert_date_to_normalized_timestamp("2023-10-18", True)
        == "2023-10-18T00:00:00.000Z"
    )
    assert (
        convert_date_to_normalized_timestamp("2023-07-18", False)
        == "2023-07-18T23:59:59.999Z"
    )
