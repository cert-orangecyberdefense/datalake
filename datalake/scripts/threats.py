from requests.sessions import PreparedRequest

from datalake import AtomValuesExtractor
from datalake.common.base_engine import BaseEngine
from datalake.helper_scripts.utils import join_dicts


class Threats(BaseEngine):

    def __init__(self, endpoint_config: dict, environment: str, tokens: list):
        super().__init__(endpoint_config, environment, tokens)
        self._post_engine_atom_values_extractor = AtomValuesExtractor(endpoint_config, environment, tokens)

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('threats')

    def _post_headers(self, output='application/json') -> dict:
        """
        Get headers for POST endpoints.

            {
                'Authorization': self.tokens[0],
                'accept': 'application/json',
                'Content-Type': 'application/json'
            }
        """
        return {'Authorization': self.tokens[0], 'Accept': output, 'Content-Type': 'application/json'}

    def _get_headers(self, output='application/json') -> dict:
        """
        Get headers for GET endpoints.

            {
                'Authorization': self.tokens[0],
                'accept': output
            }

        """
        return {'Authorization': self.tokens[0], 'accept': output}

    def bulk_lookup(self, atoms: list, atom_type=None, hashkey_only=False, output="application/json") -> dict:
        """
        Use to look up atoms in API.

        :param atoms: atoms that needs to be looked up.
        :param atom_type: must be one of the authorized_atom_value
        """
        typed_atoms = {}
        authorized_output = ['application/json', 'text/csv']

        if not atom_type:
            atoms_values_extractor_response = self._post_engine_atom_values_extractor.atom_values_extract(
                atoms)
            if atoms_values_extractor_response['found'] > 0:
                typed_atoms = join_dicts(
                    typed_atoms, atoms_values_extractor_response['results'])
            else:
                raise ValueError('none of your atoms could be typed')
        elif atom_type not in self._post_engine_atom_values_extractor.authorized_atom_value:
            raise ValueError(f'{atom_type} atom_type could not be treated')
        else:
            typed_atoms[atom_type] = atoms
        if output and output not in authorized_output:
            raise ValueError(f'{output} output type not authorized')

        accept_header = {'Accept': output}
        body = typed_atoms
        body['hashkey_only'] = hashkey_only
        url = self._build_url_for_endpoint('threats-bulk-lookup')
        response = self.datalake_requests(url, 'post', {**self._post_headers(), **accept_header}, body)
        return response

    def lookup(self, atom_value, atom_type=None, hashkey_only=False, output="application/json"):

        """
        Use to look up a threat in API.

        :param atom_value: threat that needs to be looked up.
        :param atom_type: must be one of the authorized_atom_value.
                        if this atom_type is not given, it'll be defined at the cost of an API call.
        """
        authorized_output = [
            'application/json',
            'text/csv',
            'application/x-misp+json'
            'applicatin/stix+json'
        ]

        if not atom_type:
            threats = [atom_value]
            atoms_values_extractor_response = self._post_engine_atom_values_extractor.atom_values_extract(
                threats)
            if atoms_values_extractor_response['found'] > 0:
                atom_type = list(
                    atoms_values_extractor_response['results'].keys())[0]
            else:
                raise ValueError('your atom could not be typed')
        elif atom_type not in self._post_engine_atom_values_extractor.authorized_atom_value:
            raise ValueError(f'{atom_type} atom_type could not be treated')
        if output and output not in authorized_output:
            raise ValueError(f'{output} output type not authorized')

        url = self._build_url_for_endpoint('lookup')
        params = {'atom_value': atom_value, 'atom_type': atom_type, 'hashkey_only': hashkey_only}
        req = PreparedRequest()
        req.prepare_url(url, params)
        response = self.datalake_requests(req.url, 'get', {**self._get_headers()})
        return response
