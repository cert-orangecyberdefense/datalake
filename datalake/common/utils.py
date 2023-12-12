import datetime
import json
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
        csv_lines = response.strip().split("\n")
        if not aggregated_response:
            aggregated_response = [csv_lines[0]]
        aggregated_response += csv_lines[1:]
    return aggregated_response


def parse_api_timestamp(timestamp: str) -> Optional[datetime.datetime]:
    if timestamp:
        timestamp = timestamp.split("+")[
            0
        ]  # Discard the offset as it should be 0 and is not supported by python 3.6
        return datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
    return None


def split_list(list_to_split: list, slice_size: int) -> Generator[list, None, None]:
    for i in range(0, len(list_to_split), slice_size):
        yield list_to_split[i : i + slice_size]


def get_error_message(resp_body: dict):
    if "msg" in resp_body:
        return resp_body.get("msg")
    elif "message" in resp_body:
        return resp_body.get("message")
    elif "messages" in resp_body:
        return resp_body.get("messages")
    else:
        raise ValueError("no error message in api response")


def save_output(file_name: str, data, cls=None):
    """
    Save the data in a file.
    If data is dict, file format will be JSON.
    If data is a list, file format will be txt.
    Else it will be saved as it comes.
    """
    with open(file_name, "w+") as file_to_write:
        if isinstance(data, dict):
            file_to_write.write(json.dumps(data, sort_keys=True, indent=2, cls=cls))
        elif isinstance(data, list):
            for item in data:
                file_to_write.write(f"{item}\n")
        else:
            file_to_write.write(data)


def check_normalized_timestamp(ts: str) -> bool:
    """
    Check if the provided timestamp is in a normalized format
    """
    try:
        if (
            ts
            != datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )[:-3]
            + "Z"
        ):
            raise ValueError
        return True
    except ValueError:
        return False


def convert_date_to_normalized_timestamp(date_input: str, start: bool) -> str:
    """
    Convert a given date into a normalized timestamp format
    Either at the begining of the day (start at True) or at the end (start at False)
    """
    try:
        if start:
            date_ts = date_input + "T00:00:00.000Z"
        else:
            date_ts = date_input + "T23:59:59.999Z"
        if check_normalized_timestamp(date_ts):
            return date_ts
        else:
            raise ValueError
    except:
        raise ValueError


def load_json(file_name: str) -> dict:
    return json.load(open(file_name))


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)
