from typing import Generator


def split_list(list_to_split: list, slice_size: int) -> Generator[list, None, None]:
    for i in range(0, len(list_to_split), slice_size):
        yield list_to_split[i:i + slice_size]
