import datetime
from collections import defaultdict
from typing import Dict, Optional, Generator


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


def aggregate_csv_or_json_api_response(aggregated_response, response):
    if isinstance(response, dict):  # json response
        aggregated_response = join_dicts(aggregated_response, response)
    else:  # csv response
        csv_lines = response.strip().split('\n')
        if not aggregated_response:
            aggregated_response = [csv_lines[0]]
        aggregated_response += csv_lines[1:]
    return aggregated_response


def parse_api_timestamp(timestamp: str) -> Optional[datetime.datetime]:
    if timestamp:
        timestamp = timestamp.split('+')[0]  # Discard the offset as it should be 0 and is not supported by python 3.6
        return datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f')
    return None


def split_list(list_to_split: list, slice_size: int) -> Generator[list, None, None]:
    for i in range(0, len(list_to_split), slice_size):
        yield list_to_split[i:i + slice_size]
