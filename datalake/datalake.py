import logging

from datalake import AtomType
from datalake.common.base_script import BaseScripts
from datalake.scripts.threats import Threats
from datalake.scripts.bulk_search import BulkSearch


class ConfigArg:
    def __init__(self, loglevel: int, env: str) -> None:
        self.loglevel = loglevel
        self.env = env


class Datalake:
    """ Base Datalake class

    Usage:
    >>> dtl = Datalake(username='some username', password='some password')
    >>> dtl.Threats.lookup(atom_value='mayoclinic.org', atom_type=AtomType.DOMAIN, hashkey_only=False)
    """

    LOG_LEVEL = logging.WARNING

    def __init__(self, username: str = None, password: str = None, env='prod'):
        self.username = username
        self.password = password
        self.env = env
        args = ConfigArg(loglevel=self.LOG_LEVEL, env=env)
        self.starter = BaseScripts()
        endpoint_config, _, tokens = self.starter.load_config(args=args, username=self.username, password=self.password)
        self.tokens = tokens
        self.endpoint_config = endpoint_config

        self.Threats = Threats(endpoint_config, env, tokens)
        self.BulkSearch = BulkSearch(endpoint_config, env, tokens)
