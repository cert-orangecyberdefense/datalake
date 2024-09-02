from typing import List, Tuple

from datalake.endpoints.endpoint import Endpoint
from datalake.common.output import parse_response


class Sources(Endpoint):
    def check_sources(self, sources_list: List[str]) -> Tuple[bool, List[str]]:
        """
        Check the list of sources (their ids) provided in a a list
        Return two elements:
        - a boolean set to True if all sources exists in Datalake, False otherwise
        - a list containing the non-existing sources ids
        """
        url = self._build_url_for_endpoint("sources")
        url = url + "?limit=1000&description_only=true"
        for source in sources_list:
            url = url + "&source_ids=" + source
        response = parse_response(
            self.datalake_requests(url, "get", self._get_headers())
        )
        if response["count"] == len(sources_list):
            return True, []
        else:
            valid_sources = [
                response["results"][x]["id"] for x in range(0, len(response["results"]))
            ]
            invalid_sources = [
                sources_list[y]
                for y in range(0, len(sources_list))
                if sources_list[y] not in valid_sources
            ]
            return False, invalid_sources
