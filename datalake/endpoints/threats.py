from typing import List

from requests.sessions import PreparedRequest

from datalake import AtomType
from datalake.common.ouput import Output, output_supported, parse_response
from datalake.endpoints.endpoint import Endpoint
from datalake.common.utils import join_dicts


class Threats(Endpoint):

    @output_supported({Output.JSON, Output.CSV})
    def bulk_lookup(
            self,
            atom_values: list,
            atom_type: AtomType = None,
            hashkey_only=False,
            output=Output.JSON
    ) -> dict:
        """
        Look up multiple threats at once in the API, returning their ids and if they are present in Datalake.

        Compared to the lookup endpoint, it allow to lookup big batch of values faster as fewer API calls are made.
        However, fewer outputs types are supported as of now.
        """
        typed_atoms = {}
        if not atom_type:
            atoms_values_extractor_response = self.atom_values_extract(atom_values)
            if atoms_values_extractor_response['found'] > 0:
                typed_atoms = join_dicts(typed_atoms, atoms_values_extractor_response['results'])
            else:
                raise ValueError('none of your atoms could be typed')
        elif not isinstance(atom_type, AtomType):
            raise ValueError(f'{atom_type} atom_type could not be treated')
        else:
            typed_atoms[atom_type.value] = atom_values

        body: dict = typed_atoms
        body['hashkey_only'] = hashkey_only
        url = self._build_url_for_endpoint('threats-bulk-lookup')
        response = self.datalake_requests(url, 'post', self._post_headers(output=output), body)
        return parse_response(response)

    @output_supported({Output.JSON, Output.CSV, Output.MISP, Output.STIX})
    def lookup(self, atom_value, atom_type: AtomType = None, hashkey_only=False, output=Output.JSON) -> dict:
        """
        Look up a threat in the API, returning its id (called threat's hashkey) and if it is present in Datalake.

        The hashkey is also based on the threat type.
        If atom_type is not specified, another query to the API will be made to determine it.
        With hashkey_only = False, the full threat details are returned in the requested format.
        """
        atom_type_str = None
        if not atom_type:
            threats = [atom_value]
            atoms_values_extractor_response = self.atom_values_extract(threats)
            if atoms_values_extractor_response['found'] > 0:
                atom_type_str = list(atoms_values_extractor_response['results'].keys())[0]
            else:
                raise ValueError('atom could not be typed')
        elif not isinstance(atom_type, AtomType):
            raise ValueError(f'{atom_type} atom_type could not be treated')
        else:  # atom_type is a valid enum passed by the user
            atom_type_str = atom_type.value

        url = self._build_url_for_endpoint('lookup')
        params = {'atom_value': atom_value, 'atom_type': atom_type_str, 'hashkey_only': hashkey_only}
        req = PreparedRequest()
        req.prepare_url(url, params)
        response = self.datalake_requests(req.url, 'get', self._get_headers(output=output))
        return parse_response(response)

    def atom_values_extract(self, untyped_atoms: List[str], treat_hashes_like=AtomType.FILE) -> dict:
        """
        Determine the types of atoms passed.

        values that are believed to be hashes will be returned as <treat_hashes_like>
        """
        url = self._build_url_for_endpoint('atom-values-extract')
        payload = {
            'content': ' '.join(untyped_atoms),
            'treat_hashes_like': treat_hashes_like.value
        }
        return self.datalake_requests(url, 'post', self._post_headers(), payload).json()
