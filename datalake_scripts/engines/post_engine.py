"""All the engines that use a GET endpoint."""
import os
from typing import Set, Dict, List, Union

from requests import PreparedRequest

from datalake_scripts.common.base_engine import BaseEngine
from datalake_scripts.common.logger import logger
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
        """
        Get headers for GET endpoints.

            {
                'Authorization': self.tokens[0],
                'accept': 'application/json',
                'Content-Type': 'application/json'
            }
        """
        return {'Authorization': self.tokens[0], 'accept': 'application/json', 'Content-Type': 'application/json'}

    @staticmethod
    def build_full_query_body(query_body):
        if not isinstance(query_body, dict) and 'AND' not in query_body:
            raise ValueError('Query body is not valid: top level "AND" is missing')
        return query_body


class ThreatsPost(PostEngine):
    """
    Add new threat to the API
    """

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('threats-manual')

    @staticmethod
    def parse_threat_types(threat_types: list) -> dict:
        threat_type_parsed = {}
        for i in range(0, len(threat_types), 2):
            threat_type = threat_types[i]
            score = int(threat_types[i + 1])
            if threat_type not in PostEngine.authorized_threats_value:
                raise ValueError(f'Unknow threat_types: {threat_type} {score},'
                                 f' please use only value in {PostEngine.authorized_threats_value}.')
            if score < 0 or score > 100:
                raise ValueError(f'Wrong score: {threat_type} {score}, '
                                 'please use only value in [0, 100].')
            threat_type_parsed[threat_type] = int(score)
        return threat_type_parsed

    @staticmethod
    def get_whitelist_threat_types() -> dict:
        return {threat_type: 0 for threat_type in PostEngine.authorized_threats_value}

    def _add_new_atom(self, atom_value: str, atom_type: str, payload: dict, links: list) -> dict:
        final_payload = self._tune_payload_to_atom(atom_type, links, payload, atom_value)
        return self.datalake_requests(self.url, 'post', self._post_headers(), final_payload)

    def _tune_payload_to_atom(self, atom_type, links, payload, value):
        atom_type = atom_type.lower()
        key_value = atom_type + '_content'
        if atom_type == 'apk':
            payload['threat_data']['content'][key_value] = {'android': {'package_name': value}}
        elif atom_type == 'as':
            payload['threat_data']['content'][key_value] = {'asn': int(value)}
        elif atom_type == 'cc':
            payload['threat_data']['content'][key_value] = {'number': int(value)}
        elif atom_type == 'crypto':
            address, network = value.split()
            payload['threat_data']['content'][key_value] = {'crypto_address': address, 'crypto_network': network}
        elif atom_type == 'cve':
            payload['threat_data']['content'][key_value] = {'cve_id': value}
        elif atom_type == 'domain':
            payload['threat_data']['content'][key_value] = {'domain': value}
        elif atom_type == 'email':
            payload['threat_data']['content'][key_value] = {'email': value}
        elif atom_type == 'file' or atom_type == 'ssl':
            HASH_LIST = {'32': 'md5', '40': 'sha1', '64': 'sha256', '128': 'sha512'}
            hash_key = HASH_LIST.get(str(len(value)))
            if not hash_key:
                hash_key = 'ssdeep'
            payload['threat_data']['content'][key_value] = {'hashes': {hash_key: value}}
        elif atom_type == 'fqdn':
            payload['threat_data']['content'][key_value] = {'fqdn': value}
        elif atom_type == 'iban':
            payload['threat_data']['content'][key_value] = {'iban': value}
        elif atom_type == 'ip':
            ip_type = 4 if '.' in value else 6
            payload['threat_data']['content'][key_value] = {'ip_address': value, 'ip_version': ip_type}
        elif atom_type == 'ip_range':
            payload['threat_data']['content'][key_value] = {'cidr': value}
        elif atom_type == 'regkey':
            payload['threat_data']['content'][key_value] = {'path': value}
        elif atom_type == 'paste' or atom_type == 'url':
            payload['threat_data']['content'][key_value] = {'url': value}
        elif atom_type == 'phone_number':
            key = 'international_phone_number' if value.startswith('+') else 'national_phone_number'
            payload['threat_data']['content'][key_value] = {key: value}
        else:
            raise ValueError(f'Unknow threat_types: {atom_type},\n'
                             f'_authorized_atom_value: {self.authorized_atom_value}')
        if links:
            payload['threat_data']['content'][key_value].update({'external_analysis_link': links})
        return payload

    def add_threats(self, atom_list: list, atom_type: str, is_whitelist: bool, threats_score: Dict[str, int],
                    is_public: bool, tags: list, links: list, override_type: str) -> dict:
        """
        Use it to add a list of threats to the API.

        :param atom_list: atoms that needs to be added.
        :param atom_type: must be one of the _authorized_atom_value
        :param is_whitelist: if true the score will be set to 0
        :param threats_score:  a dict that contain {threat_type -> score}
        :param is_public: if true the added threat will be public else will be reserved to organization
        :param tags: a list of tags to add
        :param links: external_analysis_link to include with each atoms
        :param override_type: either 'permanent' or 'temporary'. Permanent don't allow future automatic score change
        """
        payload = {
            'override_type': override_type,
            'public': is_public,
            'threat_data': {
                'content': {},
                'scores': [],
                'threat_types': [],
                'tags': tags
            }
        }
        if is_whitelist:
            for threat in self.authorized_threats_value:
                payload['threat_data']['scores'].append({'score': {'risk': 0}, 'threat_type': threat})
                payload['threat_data']['threat_types'].append(threat)
        else:
            for threat, score in threats_score.items():
                payload['threat_data']['scores'].append({'score': {'risk': score}, 'threat_type': threat})
                payload['threat_data']['threat_types'].append(threat)

        return_value = {'results': []}
        for atom in atom_list:
            if not atom:  # empty value
                logger.info(f'EMPTY ATOM {atom.ljust(self.terminal_size - 6, " ")} \x1b[0;30;41m  KO  \x1b[0m')
                continue
            response_dict = self._add_new_atom(atom, atom_type, payload, links)

            if response_dict.get('atom_value'):
                logger.info(atom.ljust(self.terminal_size - 6, ' ') + '\x1b[0;30;42m' + '  OK  ' + '\x1b[0m')
                return_value['results'].append(response_dict)
            else:
                logger.info(atom.ljust(self.terminal_size - 6, ' ') + '\x1b[0;30;41m' + '  KO  ' + '\x1b[0m')
                logger.debug(response_dict)
        return return_value


class BulkThreatsPost(PostEngine, HandleBulkTaskMixin):
    """
    Add multiple threats to the API through a single call
    """

    OCD_DTL_MAX_BULK_THREATS_TIME = int(os.getenv('OCD_DTL_MAX_BULK_THREATS_TIME', 600))
    OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT = int(os.getenv('OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT', 10))

    def _batch_size(self):
        return self.endpoint_config['threats-manual-bulk-size']

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('threats-manual-bulk')

    def add_bulk_threats(self, atom_list: list, atom_type: str, is_whitelist: bool, threats_score: Dict[str, int],
                         is_public: bool, tags: list, links: list, override_type: str) -> set:
        """create threats and return their hashkeys"""
        atom_type = atom_type.lower()
        payload = {
            'atom_type': atom_type,
            'override_type': override_type,
            'public': is_public,
            'scores': [],
            'tags': tags
        }

        # Build score payload
        if is_whitelist:
            for threat in self.authorized_threats_value:
                payload['scores'].append({'score': {'risk': 0}, 'threat_type': threat})
        else:
            for threat, score in threats_score.items():
                payload['scores'].append({'score': {'risk': score}, 'threat_type': threat})

        if links:
            threat_data = {'content': {f'{atom_type}_content': {'external_analysis_link': links}}}
            payload['threat_data'] = threat_data

        hashkey_created = self.queue_bulk_threats(atom_list, payload)
        return hashkey_created

    def queue_bulk_threats(self, atom_list, payload):
        hashkey_created = []
        bulk_in_flight = []  # bulk task uuid unchecked

        for batch in split_list(atom_list, self._batch_size()):
            if len(bulk_in_flight) >= self.OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT:
                bulk_threat_task_uuid = bulk_in_flight.pop(0)
                hashkey_created += self.check_bulk_threats_added(bulk_threat_task_uuid)

            payload['atom_values'] = '\n'.join(batch)  # Raw csv expected
            response = self.datalake_requests(self.url, 'post', self._post_headers(), payload)

            task_uid = response.get('task_uuid')
            if task_uid:
                bulk_in_flight.append(response['task_uuid'])
            else:
                logger.warning(f'batch of threats from {batch[0]} to {batch[-1]} failed to be created')

        # Finish to check the other bulk tasks
        for bulk_threat_task_uuid in bulk_in_flight:
            hashkey_created += self.check_bulk_threats_added(bulk_threat_task_uuid)

        nb_threats = len(hashkey_created)
        if nb_threats > 0:
            ok_sign = '\x1b[0;30;42m' + '  OK  ' + '\x1b[0m'
            logger.info(f'Created {nb_threats} threats'.ljust(self.terminal_size - 6, ' ') + ok_sign)
        else:
            ko_sign = '\x1b[0;30;41m' + '  KO  ' + '\x1b[0m'
            logger.info(f'Failed to create any threats'.ljust(self.terminal_size - 6, ' ') + ko_sign)
        return set(hashkey_created)

    def check_bulk_threats_added(self, bulk_threat_task_uuid) -> list:
        """Check if the bulk manual threat submission completed successfully and if so return the hashkeys created"""

        def is_completed_task(json_response):
            return json_response['state'] in ('DONE', 'CANCELLED')

        hashkey_created = []
        url = self._build_url_for_endpoint('retrieve-threats-manual-bulk')

        try:
            response = self.handle_bulk_task(
                bulk_threat_task_uuid,
                url,
                timeout=self.OCD_DTL_MAX_BULK_THREATS_TIME,
                additional_checks=[is_completed_task]
            )
        except TimeoutError:
            response = {}

        hashkeys = response.get('hashkeys')
        atom_values = response.get('atom_values')

        # if the state is not DONE we consider the batch a failure
        if hashkeys and response.get('state', 'CANCELLED') == 'DONE':
            for hashkey in hashkeys:
                hashkey_created.append(hashkey)
        else:
            # default values in case the json is missing some fields
            hashkeys = hashkeys or ['<missing value>']
            atom_values = atom_values or ['<missing value>']
            logger.warning(f'batch of threats from {atom_values[0]}({hashkeys[0]}) to {atom_values[-1]}({hashkeys[-1]})'
                           f' failed to be created during task {bulk_threat_task_uuid}')
        return hashkey_created


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
            if response.get('message'):
                logger.warning('\x1b[6;30;41m' + hashkey + ': ' + response.get('message') + '\x1b[0m')
                return_value.append(hashkey + ': ' + response.get('message'))
            else:
                return_value.append(hashkey + ': OK')
                logger.info('\x1b[6;30;42m' + hashkey + ': OK\x1b[0m')
        return return_value


class TagsPost(PostEngine):
    """
    Threats tags engine.
    """

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('tag')

    def _post_tags_to_hashkey(self, hashkey: str, tags: List[str], visibility: str = 'organization') -> dict:
        """
        Post tags on a single threat hashkey
        """
        tags_payload = []
        for tag in tags:
            tags_payload.append(
                {
                    'name': tag,
                    'visibility': visibility,
                }
            )
        payload = {
            'tags': tags_payload,
        }
        url = self.url.format(hashkey=hashkey)
        logger.debug(url)
        return self.datalake_requests(url, 'post', self._post_headers(), payload)

    def post_tags(self, hashkeys: Set[str], tags: List[str], *, public=True) -> list:
        """
        Post tags on threat hashkeys
        """
        visibility = 'public' if public else 'organization'
        return_value = []
        for hashkey in hashkeys:
            response = self._post_tags_to_hashkey(hashkey, tags, visibility)
            if response.get('message'):
                logger.warning('\x1b[6;30;41m' + hashkey + ': ' + response.get('message') + '\x1b[0m')
                return_value.append(hashkey + ': ' + response.get('message'))
            else:
                return_value.append(hashkey + ': OK')
                logger.info('\x1b[6;30;42m' + hashkey + ': OK\x1b[0m')
        return return_value


class ScorePost(PostEngine):
    """
    Threats score engine.
    """

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('threats')

    def _post_new_score(self, hashkey: str, scores: Dict[str, int], override_type: str = 'temporary') -> dict:
        """
        Post new score to the API
        """
        payload = {
            'override_type': override_type,
            'scores': []
        }
        for threat_type, score in scores.items():
            if score is None:
                return {'message': 'No score to modify'}
            payload['scores'].append(
                {
                    'threat_type': threat_type,
                    'score': {
                        'risk': score
                    }
                }
            )

        logger.debug('url : ' + repr(self.url))
        return self.datalake_requests(f'{self.url}{hashkey}/scoring-edits/', 'post', self._post_headers(), payload)

    def post_new_score_from_list(self, hashkeys: list, scores: Dict[str, int],
                                 override_type: str = 'temporary') -> list:
        """
        Post new score to the API from a list of hashkeys
        """
        return_value = []
        for hashkey in hashkeys:
            response = self._post_new_score(hashkey, scores, override_type)
            if response.get('message'):
                logger.warning('\x1b[6;30;41m' + hashkey + ': ' + response.get('message') + '\x1b[0m')
                return_value.append(hashkey + ': ' + response.get('message'))
            else:
                return_value.append(hashkey + ': OK')
                logger.info('\x1b[6;30;42m' + hashkey + ': OK\x1b[0m')
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
        body = {"query_fields": query_fields}
        if query_body:
            body['query_body'] = self.build_full_query_body(query_body)
        else:
            body['query_hash'] = query_hash

        response = self.datalake_requests(self.url, 'post', post_body=body, headers=self._post_headers())
        if not response:
            logger.error('No bulk search created, is the query_hash valid as well as the query_fields ?')
            return {}
        return self._handle_bulk_search_task(task_uuid=response['task_uuid'])


class AdvancedSearch(PostEngine):
    """Advanced search engine."""

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('advanced-search')

    def get_threats(self, query_body: BaseEngine.Json, limit=10) -> dict:
        query_body = self.build_full_query_body(query_body)
        payload = {
            "limit": limit,
            "offset": 0,
            "query_body": query_body
        }
        return self.datalake_requests(self.url, 'post', self._post_headers(), payload)
