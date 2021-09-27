import datetime
from collections import defaultdict
from typing import Dict, Optional


def join_dicts(*dicts: dict) -> Dict[str, list]:
    """Takes two or more dictionaries and join them"""
    if len(dicts) == 0:
        return {}
    if len(dicts) == 1:
        return dicts[0]

    out = defaultdict(list)
    for d in dicts:
        for key, val in d.items():
            out[key].extend(val)
    return out


def parse_api_timestamp(timestamp: str) -> Optional[datetime.datetime]:
    if timestamp:
        timestamp = timestamp.split('+')[0]  # Discard the offset as it should be 0 and is not supported by python 3.6
        return datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f')
    return None
