from datalake.endpoints.endpoint import Endpoint
from datalake.common.ouput import parse_response, Output, output_supported


class AdvancedSearch(Endpoint):
    @output_supported({Output.JSON, Output.STIX, Output.MISP, Output.CSV})
    def advanced_search_from_query_body(self, query_body: dict, limit: int = 20, offset: int = 0):
        if not query_body:
            raise ValueError("query_body is required")
        body = {
            'query_body': query_body,
            'limit': limit,
            'offset': offset,
        }
        url = self._build_url_for_endpoint('advanced-search')
        response = self.datalake_requests(url, 'post', post_body=body, headers=self._post_headers())
        return parse_response(response)

    def advanced_search_from_query_hash(self, query_hash, limit, offset):
        ...
