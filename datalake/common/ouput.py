from enum import Enum
from typing import Set, Union

from requests import Response


class Output(Enum):
    JSON = 'application/json'
    CSV = 'text/csv'
    MISP = 'application/x-misp+json'
    STIX = 'application/stix+json'
    JSON_ZIP = 'application/zip'
    CSV_ZIP = 'text/x-csv-zip'
    STIX_ZIP = 'text/x-stix-zip'

    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)


def parse_response(response: Response) -> Union[str, dict]:
    """Parse a Request.Response depending of the Content-Type returned"""
    content_type = response.headers.get('Content-Type', Output.JSON.value)
    content_type = content_type.split(';')[0]  # we don't care about extra info on the content
    if content_type in {output.value for output in [Output.CSV, Output.CSV_ZIP, Output.JSON_ZIP]}:
        return response.text
    else:
        return response.json()


def display_outputs(outputs):
    return ', '.join(sorted([str(output) for output in outputs]))


def output_supported(outputs: Set[Output]):
    def inner_decorator(function):
        def wrapper(*args, **kwargs):
            if kwargs.get('output') and kwargs['output'] not in outputs:
                raise ValueError(f'{kwargs["output"]} output type is not supported. '
                                 f'Outputs supported are: {display_outputs(outputs)}')
            return function(*args, **kwargs)
        return wrapper
    return inner_decorator
