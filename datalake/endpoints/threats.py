from typing import List

from requests.sessions import PreparedRequest

from datalake import AtomType
from datalake.common.ouput import Output, output_supported
from datalake.endpoints.endpoint import Endpoint
from datalake.helper_scripts.utils import join_dicts


class Threats(Endpoint):

    @output_supported({Output.JSON, Output.CSV})
    def bulk_lookup(
            self,
            atom_values: list,
            atom_type: AtomType = None,
            hashkey_only=False,
            output=Output.JSON
    ) -> dict:
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

        body = typed_atoms
        body['hashkey_only'] = hashkey_only
        url = self._build_url_for_endpoint('threats-bulk-lookup')
        response = self.datalake_requests(url, 'post', self._post_headers(output=output), body)
        return response

    @output_supported({Output.JSON, Output.CSV, Output.MISP, Output.STIX})
    def lookup(self, atom_value, atom_type: AtomType = None, hashkey_only=False, output=Output.JSON):
        """
        Use to look up a threat in API.

        :param atom_value: threat that needs to be looked up.
        :param atom_type: must be one of the authorized_atom_value.
                        if this atom_type is not given, it'll be defined at the cost of an API call.
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
        return response

    def atom_values_extract(self, untyped_atoms: List[str], treat_hashes_like='file') -> dict:
        url = self._build_url_for_endpoint('atom-values-extract')
        payload = {
            'content': ' '.join(untyped_atoms),
            'treat_hashes_like': treat_hashes_like
        }
        return self.datalake_requests(url, 'post', self._post_headers(), payload)
