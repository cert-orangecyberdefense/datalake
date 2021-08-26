from collections import defaultdict
from typing import Generator, Dict


def split_list(list_to_split: list, slice_size: int) -> Generator[list, None, None]:
    for i in range(0, len(list_to_split), slice_size):
        yield list_to_split[i:i + slice_size]


def join_dicts(*dicts: dict) -> Dict[str, list]:
    """ takes two or more dictionaries and join them """
    if len(dicts) == 0:
        return {}
    if len(dicts) == 1:
        return dicts[0]

    out = defaultdict(list)
    for d in dicts:
        for key, val in d.items():
            out[key].extend(val)
    return out

