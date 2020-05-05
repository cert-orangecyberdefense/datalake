"""All the engines that use a GET endpoint."""
from urllib.parse import urljoin

from typing import List

from requests import PreparedRequest

from datalake_scripts.common.base_engine import BaseEngine
from datalake_scripts.common.logger import logger


class GetEngine(BaseEngine):
    """
    Common engine for all the GET endpoints.
    """

    def _get_headers(self) -> dict:
        """
        Get headers for GET endpoints.

            {
                'Authorization': self.tokens[0],
                'accept': 'application/json'
            }

        """
        return {'Authorization': self.tokens[0], 'accept': 'application/json'}


class ThreatsSearch(GetEngine):
    """
    Threats Search Engine
    """

    def get_json(self, list_threats: list):
        """
        Retrieve the JSON file of a list of threats and their comments.
        :return dict, list: threats found and a list of hashkey not found
        """
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
                logger.info(f'{str(index).ljust(5)}:{threat.ljust(self.terminal_size - 11)}\x1b[0;30;41mERROR\x1b[0m')
            else:
                logger.info(f'{str(index).ljust(5)}:{threat.ljust(self.terminal_size - 10)}\x1b[0;30;42m OK \x1b[0m')
                response_dict = self.datalake_requests(f'{request_url}/comments', 'get', self._get_headers(), None)
                final_dict['comments'] = response_dict
                dict_threat['results'].append(final_dict)
        return dict_threat, list_of_lost_hashes


class BulkSearch(GetEngine):
    """
    Bulk search engines
    """

    def get_threats(self, query_hash: str, query_fields: List[str] = None) -> dict:
        params = {}
        if query_fields:
            params['query_fields'] = ','.join(query_fields)
        url_without_param = urljoin(self.url, query_hash)
        req = PreparedRequest()  # Adding parameters using requests' tool
        req.prepare_url(url_without_param, params)

        response = self.datalake_requests(req.url, 'get', headers={'Authorization': self.tokens[0]})
        return response
