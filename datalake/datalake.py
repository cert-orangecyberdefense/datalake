import logging

from datalake import AtomType
from datalake.common.config import Config
from datalake.common.logger import configure_logging
from datalake.common.token_manager import TokenManager
from datalake.endpoints.threats import Threats
from datalake.endpoints.bulk_search import BulkSearch
from datalake.endpoints.tags import Tags
from datalake.endpoints.advanced_search import AdvancedSearch
from datalake.endpoints.sightings import Sightings


class Datalake:
    """ Entrypoint to the Datalake library

    Usage:
    >>> dtl = Datalake(username='some username', password='some password')
    >>> dtl.Threats.lookup(atom_value='mayoclinic.org', atom_type=AtomType.DOMAIN, hashkey_only=False)
    """

    def __init__(self, username: str = None, password: str = None, env='prod', log_level=logging.WARNING):
        configure_logging(log_level)
        endpoint_config = Config().load_config()
        token_manager = TokenManager(endpoint_config, environment=env, username=username, password=password)

        self.Threats = Threats(endpoint_config, env, token_manager)
        self.BulkSearch = BulkSearch(endpoint_config, env, token_manager)
        self.Tags = Tags(endpoint_config, env, token_manager)
        self.AdvancedSearch = AdvancedSearch(endpoint_config, env, token_manager)
        self.Sightings = Sightings(endpoint_config, env, token_manager)
