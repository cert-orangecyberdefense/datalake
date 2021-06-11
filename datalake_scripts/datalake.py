from datalake_scripts.engines.post_engine import BulkSearch
import logging
from typing import List


from datalake_scripts import Threats, LookupThreats, BulkLookupThreats, AtomValuesExtractor
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.helper_scripts.utils import join_dicts


class ConfigArg:
    def __init__(self, loglevel:int, env: str) -> None:
        self.loglevel = loglevel
        self.env = env


class Datalake:
    """ Base Datalake class
    
    Usage:
    >>> datalake = Datalake(username='some username',
                        password='some password')
    >>> datalake.look_up_threat(
        threat = 'mayoclinic.org',
        atome_type = 'domain',
        hashkey_only = False,
    )
    """
    def __init__(self, username: str, password: str, env='prod'):
        self.username = username
        self.password = password
        args = ConfigArg(loglevel=logging.WARNING, env= env)
        self.starter = BaseScripts()
        endpoint_config, _, tokens = self.starter.load_config(args=args, username=self.username, password=self.password)
        self._threats_api = Threats(endpoint_config, args.env, tokens)
        self._lookup_threats_api = LookupThreats(endpoint_config, args.env, tokens)
        self._bulk_lookup_threats_api = BulkLookupThreats(endpoint_config, args.env, tokens)
        self._post_engine_atom_values_extractor = AtomValuesExtractor(endpoint_config, args.env, tokens)
        
    def lookup_threat(self, threat, atom_type=None, hashkey_only=False) -> list:
        """
        Use to look up a threat in API.

        :param threat: threat that needs to be looked up.
        :param atom_type: must be one of the authorized_atom_value.
                          if this atom_type is not given, it'll be defined at the cost of an API call.
        """
        if not atom_type:
            threats = [threat]
            atoms_values_extractor_response = self._post_engine_atom_values_extractor.atom_values_extract(
                threats)
            if atoms_values_extractor_response['found'] > 0:
                atom_type = list(
                    atoms_values_extractor_response['results'].keys())[0]
            else:
                raise ValueError('your atom could not be typed')
        elif atom_type not in self._post_engine_atom_values_extractor.authorized_atom_value:
            raise ValueError(f'{atom_type} atom_type could not be treated')
        response = self._lookup_threats_api.get_lookup_result(
            threat, atom_type, hashkey_only)
        return response

    def bulk_lookup_threats(self, threats: list, atom_type=None, hashkey_only=False) -> dict:
        """
        Use to look up threats in API.

        :param threats: threats that needs to be looked up.
        :param atom_type: must be one of the authorized_atom_value
        """
        typed_atoms = {}
        if not atom_type:
            atoms_values_extractor_response = self._post_engine_atom_values_extractor.atom_values_extract(
                threats)
            if atoms_values_extractor_response['found'] > 0:
                typed_atoms = join_dicts(
                    typed_atoms, atoms_values_extractor_response['results'])
            else:
                raise ValueError('none of your atoms could be typed')
        elif atom_type not in self._post_engine_atom_values_extractor.authorized_atom_value:
            raise ValueError(f'{atom_type} atom_type could not be treated')
        else:
            typed_atoms[atom_type] = threats
        accept_header = {'Accept': None}
        response = self._bulk_lookup_threats_api.bulk_lookup_threats(
            typed_atoms, accept_header, hashkey_only)
        return response
