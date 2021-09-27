"""All the engines that use a GET endpoint."""

from requests import PreparedRequest

from datalake.common.logger import logger
from datalake.endpoints import Endpoint
from datalake_scripts.common.base_engine import BaseEngine


class GetEngine(BaseEngine):
    """
    Common engine for all the GET endpoints.
    """

    def _get_headers(self) -> dict:
        return {'accept': 'application/json'}


class ThreatsSearch(GetEngine):
    """
    Threats Search Engine
    """

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('threats')

    def get_json(self, list_threats: list):
        """
        Retrieve the JSON file of a list of threats and their comments.
        :return dict, list: threats found and a list of hashkey not found
        """
        terminal_size = Endpoint._get_terminal_size()
        total_hash = len(list_threats)
        dict_threat = {'count': total_hash, 'results': []}
        list_of_lost_hashes = []
        for index, threat in enumerate(list_threats):
            request_url = self.url + threat
            response_dict = self.datalake_requests(
                request_url,
                'get',
                self._get_headers(),
                None,
            )
            final_dict = response_dict
            if not response_dict.get('hashkey'):
                list_of_lost_hashes.append(threat)
                logger.info(f'{str(index).ljust(5)}:{threat.ljust(terminal_size - 11)}\x1b[0;30;41mERROR\x1b[0m')
            else:
                logger.info(f'{str(index).ljust(5)}:{threat.ljust(terminal_size - 10)}\x1b[0;30;42m OK \x1b[0m')
                response_dict = self.datalake_requests(f'{request_url}/comments', 'get', self._get_headers(), None)
                final_dict['comments'] = response_dict
                dict_threat['results'].append(final_dict)
        return dict_threat, list_of_lost_hashes


class Threats(GetEngine):
    """Retrieve threats based on an query hash using the Advanced Search endpoint
    The endpoint limit the number of result to 5 000 threats but allow more output than the bulk search
    """

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('advanced-search')

    def get_threats(self, query_hash: str, limit=10, response_format="application/json") -> dict:
        url = self.url + query_hash
        params = {'limit': limit}
        req = PreparedRequest()  # Adding parameters using requests' tool
        req.prepare_url(url, params)
        headers = {'Accept': response_format}
        response = self.datalake_requests(req.url, 'get', headers=headers)
        return response
