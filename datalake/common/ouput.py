from enum import Enum
from typing import Set


class Output(Enum):
    JSON = 'application/json'
    CSV = 'text/csv'
    MISP = 'application/x-misp+json'
    STIX = 'application/stix+json'

    def __str__(self):
        return self.name

    def __repr__(self):
        return str(self)


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
