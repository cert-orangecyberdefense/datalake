"""All the engines that use a GET endpoint."""
import os
from typing import Set, Dict, List, Union

from requests import PreparedRequest

from datalake.common.logger import logger
from datalake.endpoints import Endpoint
from datalake_scripts.common.base_engine import BaseEngine
from datalake_scripts.common.mixins import HandleBulkTaskMixin
from datalake_scripts.helper_scripts.utils import split_list


class PostEngine(BaseEngine):
    """
    Common engine for all the POST endpoints.
    """
    authorized_atom_value = [
        'apk',
        'as',
        'cc',
        'crypto',
        'cve',
        'domain',
        'email',
        'file',
        'fqdn',
        'iban',
        'ip',
        'ip_range',
        'paste',
        'phone_number',
        'regkey',
        'ssl',
        'url',
    ]

    authorized_threats_value = [
        'ddos',
        'fraud',
        'hack',
        'leak',
        'malware',
        'phishing',
        'scam',
        'scan',
        'spam',
    ]

    def _find_in_dict(self, dict_input: dict, key: str, value: str) -> dict:
        """
        Return dict result if dict key is = to value
        """
        if value == 'None':
            return {}
        for entry in dict_input:
            if entry[key] == value:
                return entry

    def _post_headers(self) -> dict:
        return {'Accept': 'application/json', 'Content-Type': 'application/json'}

    @staticmethod
    def build_full_query_body(query_body):
        if not isinstance(query_body, dict) or 'AND' not in query_body:
            raise ValueError('Query body is not valid: top level "AND" is missing')
        return query_body


class CommentsPost(PostEngine):
    """
    Threats comments engine.
    """

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('comment')

    def _post_comment(self, hashkey: str, comment: str, visibility: str = 'organization') -> dict:
        """
        Post comment on threat hashkey
        """
        payload = {
            'content': comment,
            'visibility': visibility,
        }
        url = self.url.format(hashkey=hashkey)
        logger.debug(url)
        return self.datalake_requests(url, 'post', self._post_headers(), payload)

    def post_comments(self, hashkeys: Set[str], comment: str, *, public=True) -> list:
        """
        Post comments on threats hashkey
        """
        visibility = 'public' if public else 'organization'
        return_value = []
        for hashkey in hashkeys:
            response = self._post_comment(hashkey, comment, visibility)
            if not response:
                logger.warning(f'\x1b[6;30;41m{hashkey}: KO\x1b[0m')
                return_value.append(hashkey + ': KO')
            else:
                return_value.append(hashkey + ': OK')
                logger.info(f'\x1b[6;30;42m{hashkey}: OK\x1b[0m')
        return return_value


class BulkSearch(PostEngine, HandleBulkTaskMixin):
    """
    Bulk search engines
    """

    OCD_DTL_MAX_BULK_SEARCH_TIME = int(os.getenv('OCD_DTL_MAX_BULK_SEARCH_TIME', 3600))

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('bulk-search')

    def _handle_bulk_search_task(self, task_uuid):
        retrieve_bulk_result_url = self._build_url_for_endpoint('retrieve-bulk-search')
        return self.handle_bulk_task(task_uuid, retrieve_bulk_result_url, timeout=self.OCD_DTL_MAX_BULK_SEARCH_TIME)

    def get_threats(self, query_hash: str = None, query_body: BaseEngine.Json = None, query_fields: List[str] = None) \
            -> dict:
        body = {"query_fields": query_fields} if query_fields else {}
        if query_body:
            body['query_body'] = self.build_full_query_body(query_body)
        else:
            body['query_hash'] = query_hash

        response = self.datalake_requests(self.url, 'post', post_body=body, headers=self._post_headers())
        if not response:
            logger.error('No bulk search created, is the query_hash valid as well as the query_fields ?')
            return {}
        return self._handle_bulk_search_task(task_uuid=response['task_uuid'])


class BulkLookupThreats(PostEngine):
    """Bulk Lookup Threats"""

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('threats-bulk-lookup')

    def bulk_lookup_threats(self, threats: BaseEngine.Json, additional_headers, hashkey_only: bool = True) -> dict:
        body = threats
        body['hashkey_only'] = hashkey_only
        return self.datalake_requests(self.url, 'post', {**self._post_headers(), **additional_headers}, body)


class AtomValuesExtractor(PostEngine):

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('atom-values-extract')

    def atom_values_extract(self, untyped_atoms: List[str], treat_hashes_like='file') -> dict:
        payload = {
            'content': ' '.join(untyped_atoms),
            'treat_hashes_like': treat_hashes_like
        }
        return self.datalake_requests(self.url, 'post', self._post_headers(), payload)
