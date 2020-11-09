from datalake_scripts.helper_scripts.utils import split_list


def test_split_list():
    list_to_split = [1, 2, 3, 4, 5]

    generator = split_list(list_to_split, 3)
    head = next(generator)
    tail = next(generator)

    assert head == [1, 2, 3]
    assert tail == [4, 5]


