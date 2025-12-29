import logging

from datalake.common.config import Config
from datalake.common.logger import configure_logging
from datalake.common.token_manager import TokenManager
from datalake.endpoints.threats import Threats
from datalake.endpoints.bulk_search import BulkSearch
from datalake.endpoints.comments import Comments
from datalake.endpoints.tags import Tags
from datalake.endpoints.advanced_search import AdvancedSearch
from datalake.endpoints.sightings import Sightings
from datalake.endpoints.sources import Sources
from datalake.endpoints.filtered_threat_entity import FilteredThreatEntity
from datalake.endpoints.my_account import MyAccount
from datalake.miscellaneous.search_watch import SearchWatch


class Datalake:
    """Entrypoint to the Datalake library

    Usage:
    >>> dtl = Datalake(username='some username', password='some password')
    or
    >>> dtl = Datalake(longterm_token='some longterm token')
    then
    >>> dtl.Threats.lookup(atom_value='mayoclinic.org', atom_type=AtomType.DOMAIN, hashkey_only=False)

    """

    def __init__(
        self,
        username: str = None,
        password: str = None,
        longterm_token: str = None,
        env: str = "prod",
        log_level=logging.WARNING,
        proxies: dict = None,
        verify: bool = True,
    ):
        self.logger = configure_logging(log_level)
        endpoint_config = Config().load_config()
        try:
            token_manager = TokenManager(
                endpoint_config,
                logger=self.logger,
                environment=env,
                username=username,
                password=password,
                longterm_token=longterm_token,
                proxies=proxies,
                verify=verify,
            )
        except Exception as e:
            if "Failed to resolve" in str(e) or "Failed to establish" in str(e):
                raise ConnectionError(
                    "Unable to access Datalake. Please check your network settings/connection"
                )
            else:
                raise

        # Endpoints
        self.MyAccount = MyAccount(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            proxies=proxies,
            verify=verify,
        )
        self.AdvancedSearch = AdvancedSearch(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            proxies=proxies,
            verify=verify,
        )
        self.BulkSearch = BulkSearch(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            proxies=proxies,
            verify=verify,
        )
        self.FilteredThreatEntity = FilteredThreatEntity(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            proxies=proxies,
            verify=verify,
        )
        self.Comments = Comments(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            proxies=proxies,
            verify=verify,
        )
        self.Tags = Tags(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            proxies=proxies,
            verify=verify,
        )
        self.Sources = Sources(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            proxies=proxies,
            verify=verify,
        )
        self.Threats = Threats(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            self.Sources,
            proxies=proxies,
            verify=verify,
        )
        self.Sightings = Sightings(
            self.logger,
            endpoint_config,
            env,
            token_manager,
            self.Threats,
            proxies=proxies,
            verify=verify,
        )
        # Miscellaneous
        self.SearchWatch = SearchWatch(self.logger, self.BulkSearch)

        self.logger.debug("This is a debug message after init of dtl")
