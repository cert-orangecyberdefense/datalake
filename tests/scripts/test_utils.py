from datalake.common.utils import join_dicts
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
        'k1': ['k1', 'k2', 'k3'],
        'a1': ['a1', 'a2', 'a3'],
        'b1': ['b1', 'b2'],
    }
    d2 = {
        'k1': ['k4', 'k5', 'k6'],
        'a1': ['a4', 'a5', 'a6'],
    }
    d3 = {
        'k1': ['k7', 'k8'],
        'a1': ['a7', 'a8'],
        'p1': ['p1', 'p2'],
    }

    assert join_dicts(d1, d2, d3) == {
        'k1': ['k1', 'k2', 'k3', 'k4', 'k5', 'k6', 'k7', 'k8'],
        'a1': ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8'],
        'b1': ['b1', 'b2'],
        'p1': ['p1', 'p2']
    }

