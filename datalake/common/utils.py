from collections import defaultdict
from typing import Dict


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
