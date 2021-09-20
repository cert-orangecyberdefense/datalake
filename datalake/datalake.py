import logging

from datalake import AtomType
from datalake.common.config import Config
from datalake.common.logger import configure_logging
from datalake.endpoints.threats import Threats
from datalake.endpoints.bulk_search import BulkSearch


class Datalake:
    """ Base Datalake class

    Usage:
    >>> dtl = Datalake(username='some username', password='some password')
    >>> dtl.Threats.lookup(atom_value='mayoclinic.org', atom_type=AtomType.DOMAIN, hashkey_only=False)
    """

    LOG_LEVEL = logging.WARNING

    def __init__(self, username: str = None, password: str = None, env='prod'):
        configure_logging(self.LOG_LEVEL)
        endpoint_config, _, tokens = Config().load_config(env=env, username=username, password=password)

        self.Threats = Threats(endpoint_config, env, tokens)
        self.BulkSearch = BulkSearch(endpoint_config, env, tokens)
