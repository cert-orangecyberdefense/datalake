import logging


from datalake_lib import AtomValuesExtractor
from datalake_lib.common.base_script import BaseScripts
from datalake_lib.scripts.threats import Threats
from datalake_lib.scripts.bulk_search import BulkSearch

class ConfigArg:
    def __init__(self, loglevel: int, env: str) -> None:
        self.loglevel = loglevel
        self.env = env


class Datalake:
    """ Base Datalake class

    Usage:
    >>> datalake = Datalake(username='some username', password='some password')
    >>> datalake.Threats.lookup(
    ... threat = 'mayoclinic.org',
    ... atome_type = 'domain',
    ... hashkey_only = False,
    ... )
    """
    def __init__(self, username: str, password: str, env='prod'):
        self.username = username
        self.password = password
        self.env = env
        args = ConfigArg(loglevel=logging.WARNING, env=env)
        self.starter = BaseScripts()
        endpoint_config, _, tokens = self.starter.load_config(args=args, username=self.username, password=self.password)
        self.tokens = tokens
        self.endpoint_config = endpoint_config
        self._post_engine_atom_values_extractor = AtomValuesExtractor(endpoint_config, args.env, tokens)
        self.Threats = Threats(endpoint_config, env, tokens, self._post_engine_atom_values_extractor)
        self.BulkSearch = BulkSearch(endpoint_config, env, tokens)
