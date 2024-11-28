import logging
import sys

from datalake import AtomType, SightingType, Visibility, Output
from datalake.common.config import Config
from datalake.common.logger import configure_logging
from datalake.common.token_manager import TokenManager
from datalake.endpoints.threats import Threats
from datalake.endpoints.bulk_search import BulkSearch
from datalake.endpoints.tags import Tags
from datalake.endpoints.advanced_search import AdvancedSearch
from datalake.endpoints.sightings import Sightings
from datalake.endpoints.filtered_tag_subcategory import FilteredTagSubcategory
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
        env="prod",
        log_level=logging.WARNING,
        proxies: dict = None,
        verify: bool = True,
    ):
        configure_logging(log_level)
        endpoint_config = Config().load_config()
        try:
            token_manager = TokenManager(
                endpoint_config,
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

        self.Threats = Threats(
            endpoint_config, env, token_manager, proxies=proxies, verify=verify
        )
        self.BulkSearch = BulkSearch(
            endpoint_config, env, token_manager, proxies=proxies, verify=verify
        )
        self.Tags = Tags(
            endpoint_config, env, token_manager, proxies=proxies, verify=verify
        )
        self.FilteredTagSubcategory = FilteredTagSubcategory(
            endpoint_config, env, token_manager, proxies=proxies, verify=verify
        )
        self.AdvancedSearch = AdvancedSearch(
            endpoint_config, env, token_manager, proxies=proxies, verify=verify
        )
        self.Sightings = Sightings(
            endpoint_config, env, token_manager, proxies=proxies, verify=verify
        )
        self.SearchWatch = SearchWatch(self.BulkSearch)

    def sightings_filtered_from_atom_value(
        self,
        atom_value: str,
        limit: int = None,
        offset: int = None,
        ordering: str = None,
        organization_id: int = None,
        organization_name: str = None,
        start_timestamp_date: str = None,
        end_timestamp_date: str = None,
        tags: list = None,
        sighting_type: SightingType = None,
        visibility: Visibility = None,
    ):
        atom_extract = self.Threats.atom_values_extract([atom_value])

        if atom_extract["found"] == 0:
            raise ValueError(f"No atom found for atom value: {atom_value}")
        if atom_extract["found"] > 1:
            raise ValueError(f"Multiple atoms found for atom value: {atom_value}")

        atom_detail = {}
        for k, v in atom_extract["results"].items():
            atom_detail["atom_type"] = AtomType(k)
            atom_detail["atom_value"] = v[0]
        resp = self.Threats.bulk_lookup(
            atom_values=[atom_detail["atom_value"]],
            atom_type=atom_detail["atom_type"],
            hashkey_only=True,
            output=Output.JSON,
            return_search_hashkey=False,
        )
        if not resp[atom_detail["atom_type"].value][0]["threat_found"]:
            raise ValueError(f"No threat found for atom value: {atom_value}")
        hashkey = resp[atom_detail["atom_type"].value][0]["hashkey"]

        return self.Sightings.sightings_filtered(
            hashkey,
            limit,
            offset,
            ordering,
            organization_id,
            organization_name,
            start_timestamp_date,
            end_timestamp_date,
            tags,
            sighting_type,
            visibility,
        )
