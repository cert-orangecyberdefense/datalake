"""All the engines that use a GET endpoint."""
from urllib.parse import urljoin

from typing import List

from requests import PreparedRequest

from datalake_scripts.common.base_engine import BaseEngine
from datalake_scripts.common.logger import logger
from datalake_scripts.helper_scripts.output_builder import CsvBuilder


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

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('threats')

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


class LookupThreats(GetEngine):
    """Lookup threats engine"""

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('lookup')

    def get_lookup_result(self, threat, atom_type, hashkey_only) -> list:
        params = {'atom_value': threat, 'atom_type': atom_type, 'hashkey_only': hashkey_only}
        req = PreparedRequest()  # Adding parameters using requests' tool
        req.prepare_url(self.url, params)
        response = self.datalake_requests(req.url, 'get',
                                          headers={'Authorization': self.tokens[0]})
        return response

    def lookup_threats(self, threats: list, atom_type, hashkey_only, output_type):
        boolean_to_text_and_color = {True: ('FOUND', '\x1b[6;30;42m'),
                                     False: ('NOT_FOUND', '\x1b[6;30;41m')}
        complete_response = None
        for threat in threats:
            response = self.get_lookup_result(threat, atom_type, hashkey_only)
            if not response:
                continue
            found = response['threat_found'] if 'threat_found' in response.keys() else True
            text, color = boolean_to_text_and_color[found]
            logger.info('{}{} hashkey:{} {}\x1b[0m'.format(color, threat, response['hashkey'], text))
            complete_response = {} if not complete_response else complete_response
            complete_response[threat] = response
        if output_type == 'text/csv':
            return CsvBuilder.create_csv(complete_response, atom_type)
        return complete_response
