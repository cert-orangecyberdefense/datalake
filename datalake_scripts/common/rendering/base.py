"""
Presentation layer of the CLI.

Scripts describe *what* has to be shown (a lookup report, a diff, a JSON
result...). A `Renderer` decides *how* it is shown. Scripts never know which
renderer they use: it is picked once by `get_renderer()`.
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Tuple


class Progress:
    """
    Context manager wrapping a long running step.
    The default implementation displays nothing.

        with renderer.progress("Creating bulk task") as progress:
            ...
            progress.update("Waiting for the bulk task")
    """

    def __enter__(self) -> "Progress":
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def update(self, text: str):
        pass


class Renderer(ABC):
    MAX_SEARCH_LINKS = 10

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def progress(self, text: str) -> Progress:
        """Display the progress of a long running step"""
        return Progress()

    @abstractmethod
    def item_status(self, value: str, status: str, prefix: str = ""):
        """Report the status (OK, KO...) of a single processed item"""

    @abstractmethod
    def json(self, data):
        """Display a JSON result"""

    @abstractmethod
    def user_info(self, data: dict):
        """Display the information of the current user"""

    @abstractmethod
    def threats_from_query_hash(self, response: dict, one_threat_per_line: bool):
        """Display the result of a bulk search"""

    @abstractmethod
    def bulk_lookup(self, response, output_format: str, search_url: str):
        """
        Display the result of a bulk lookup.
        :param response: aggregated API response
        :param output_format: json, csv or anything else for a human readable report
        :param search_url: GUI url of a search, to be completed with a search hashkey
        """

    @abstractmethod
    def search_watch_diff(self, diff: dict):
        """Display the added / removed threats of a search watch"""

    @staticmethod
    def _split_lookup_response(response: dict) -> Tuple[dict, List[str]]:
        """Separate the atoms (grouped by atom type) from the search hashkeys"""
        results = dict(response)
        search_hashkeys = results.pop("search_hashkey", None) or []
        return results, search_hashkeys

    def _search_links_lines(
        self, search_url: str, search_hashkeys: List[str]
    ) -> List[str]:
        if not search_hashkeys:
            return ["No search hashkeys available for this lookup."]
        if len(search_hashkeys) > self.MAX_SEARCH_LINKS:
            return [
                "Too many search hashkeys to display, check the output for the full list."
            ]
        return [
            f"Results available here : {search_url}{search_hashkey}"
            for search_hashkey in search_hashkeys
        ]
