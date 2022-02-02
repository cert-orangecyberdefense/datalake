from datalake.endpoints.endpoint import Endpoint
from datalake.common.ouput import parse_response, Output, output_supported


class AdvancedSearch(Endpoint):
    @output_supported({Output.JSON, Output.STIX, Output.MISP, Output.CSV})
    def advanced_search_from_query_body(self, query_body: dict, limit: int = 20, offset: int = 0, output=Output.JSON):
        if not query_body:
            raise ValueError("query_body is required")
        body = {
            'query_body': query_body,
            'limit': limit,
            'offset': offset,
        }
        url = self._build_url_for_endpoint('advanced-search')
        response = self.datalake_requests(url, 'post', post_body=body, headers=self._post_headers(output=output))
        return parse_response(response)

    @output_supported({Output.JSON, Output.STIX, Output.MISP, Output.CSV})
    def advanced_search_from_query_hash(self, query_hash, limit: int = 20, offset: int = 0,
                                        ordering: str = 'first_seen', output=Output.JSON):
        if not query_hash:
            raise ValueError("query_hash is required")
        ordering_list = ['first_seen', '-first-seen', 'last_updated', '-last_updated', 'events_count', '-events_count',
                         'sources_count', '-sources_count']
        if ordering not in ordering_list:
            raise ValueError(f'ordering needs to be one of the following str : {", ".join(ordering_list)}')
        url = self._build_url_for_endpoint('advanced-search-hash').format(query_hash=query_hash, limit=limit,
                                                                          offset=offset, ordering=ordering)
        response = self.datalake_requests(url, 'get', headers=self._get_headers(output=output))
        return parse_response(response)
