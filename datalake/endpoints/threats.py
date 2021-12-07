from typing import List, Union, Dict

from requests.sessions import PreparedRequest

from datalake import AtomType, ThreatType
from datalake.common.ouput import Output, output_supported, parse_response
from datalake.common.utils import split_list, aggregate_csv_or_json_api_response
from datalake.endpoints.endpoint import Endpoint


class Threats(Endpoint):
    _NB_ATOMS_PER_BULK_LOOKUP = 100

    def _bulk_lookup_batch(
            self,
            atom_values: list,
            atom_type: AtomType = None,
            hashkey_only=False,
            output=Output.JSON
    ) -> dict:
        """Bulk lookup done on maximum _NB_ATOMS_PER_BULK_LOOKUP atoms"""
        typed_atoms = {}
        if not atom_type:
            atoms_values_extractor_response = self.atom_values_extract(atom_values)
            if atoms_values_extractor_response['found'] > 0:
                typed_atoms = atoms_values_extractor_response['results']
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

    @output_supported({Output.JSON, Output.CSV})
    def bulk_lookup(
            self,
            atom_values: list,
            atom_type: AtomType = None,
            hashkey_only=False,
            output=Output.JSON
    ) -> Union[dict, str]:
        """
        Look up multiple threats at once in the API, returning their ids and if they are present in Datalake.

        Compared to the lookup endpoint, it allow to lookup big batch of values faster as fewer API calls are made.
        However, fewer outputs types are supported as of now.
        """
        aggregated_response = [] if output is Output.CSV else {}
        for atom_values_batch in split_list(atom_values, self._NB_ATOMS_PER_BULK_LOOKUP):
            batch_result = self._bulk_lookup_batch(atom_values_batch, atom_type, hashkey_only, output)
            aggregated_response = aggregate_csv_or_json_api_response(
                aggregated_response,
                batch_result,
            )
        if output is Output.CSV:
            aggregated_response = '\n'.join(aggregated_response)  # a string is expected for CSV output
        return aggregated_response

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

    def edit_score_by_hashkeys(self, hashkeys, scores_list, permanent):
        if type(hashkeys) is not list or not hashkeys:
            raise ValueError('Hashkeys has to be a list of string')
        if all(type(hashkey) is not str or not hashkey for hashkey in hashkeys):
            raise ValueError('Hashkeys has to be a list of string')

        override_type = 'permanent' if permanent else 'temporary'
        req_body = {
            'override_type': override_type,
            'hashkeys': hashkeys,
            'scores': self.__build_scores(scores_list)
        }
        url = self._build_url_for_endpoint('bulk-scoring-edits')
        response = self.datalake_requests(url, 'post', self._post_headers(), req_body)
        return parse_response(response)

    def edit_score_by_query_body_hash(self, query_body_hash, scores_list, permanent):
        override_type = 'permanent' if permanent else 'temporary'
        req_body = {
            'override_type': override_type,
            'query_body_hash': query_body_hash,
            'scores': self.__build_scores(scores_list)
        }
        url = self._build_url_for_endpoint('bulk-scoring-edits')
        response = self.datalake_requests(url, 'post', self._post_headers(), req_body)
        return parse_response(response)

    @staticmethod
    def __build_scores(scores_list: List[Dict[str, int]]):
        scores_body = []
        for score_dict in scores_list:
            if not isinstance(score_dict['threat_type'], ThreatType):
                raise ValueError('Invalid threat_type input')
            if score_dict['score'] > 100 or score_dict['score'] < 0:
                raise ValueError('Invalid score input, min: 0, max: 100')

            scores_body.append({
                'score': {
                    'risk': score_dict['score']
                },
                'threat_type': score_dict['threat_type'].value
            })
        return scores_body
