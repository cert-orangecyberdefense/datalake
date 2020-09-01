"""All the engines that use a GET endpoint."""
import os
from time import time, sleep
from typing import Set, Dict, List

import requests

from datalake_scripts.common.base_engine import BaseEngine
from datalake_scripts.common.logger import logger


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

    def _add_new_atom(self, value: str, atom_type: str, payload: dict, links: list) -> dict:
        """
        Create the correct payload to add a new threat to the API.
        """
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
        elif atom_type == 'ip':
            ip_type = 4 if '.' in value else 6
            payload['threat_data']['content'][key_value] = {'ip_address': value, 'ip_version': ip_type}
        elif atom_type == 'ip_range':
            payload['threat_data']['content'][key_value] = {'cidr': value}
        elif atom_type == 'paste' or atom_type == 'url':
            payload['threat_data']['content'][key_value] = {'url': value}
        else:
            raise ValueError(f'Unknow threat_types: {atom_type},\n'
                             f'_authorized_atom_value: {self.authorized_atom_value}')
        if links:
            payload['threat_data']['content'][key_value].update({'external_analysis_link': links})
        return payload

    def add_threats(self, atom_list: list, atom_type: str, white: bool, threats_score: Dict[str, int], is_public: bool,
                    tags: list, links: list, override_type: str) -> dict:
        """
        Use it to add a list of threats to the API.

        :param atom_list: atoms that needs to be added.
        :param atom_type: must be one of the _authorized_atom_value
        :param white: if true the score will be set to 0
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
        if white:
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
            final_payload = self._add_new_atom(atom, atom_type, payload, links)
            response_dict = self.datalake_requests(self.url, 'post', self._post_headers(), final_payload)
            if response_dict.get('atom_value'):
                return_value['results'].append(response_dict)
                logger.info(atom.ljust(self.terminal_size - 6, ' ') + '\x1b[0;30;42m' + '  OK  ' + '\x1b[0m')
            else:
                logger.info(atom.ljust(self.terminal_size - 6, ' ') + '\x1b[0;30;41m' + '  KO  ' + '\x1b[0m')
                logger.debug(response_dict)

        return return_value


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


class BulkSearch(PostEngine):
    """
    Bulk search engines
    """

    OCD_DTL_MAX_BACK_OFF_TIME = int(os.getenv('OCD_DTL_MAX_BACK_OFF_TIME', 120))
    OCD_DTL_MAX_BULK_SEARCH_TIME = int(os.getenv('OCD_DTL_MAX_BULK_SEARCH_TIME', 3600))

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('bulk-search')

    def _handle_bulk_search_task(self, task_uuid):
        retrieve_bulk_result_url = self._build_url_for_endpoint('retrieve-bulk-search')
        retrieve_bulk_result_url = retrieve_bulk_result_url.format(task_uuid=task_uuid)

        start_time = time()
        back_off_time = 10

        json_response = None
        while not json_response:
            response = requests.get(url=retrieve_bulk_result_url, headers={'Authorization': self.tokens[0]})
            if response.status_code == 200:
                json_response = response.json()
            elif response.status_code == 401:
                logger.debug('Refreshing expired Token')
                self._token_update(response.json())
            elif time() - start_time + back_off_time < self.OCD_DTL_MAX_BULK_SEARCH_TIME:
                sleep(back_off_time)
                back_off_time = min(back_off_time * 2, self.OCD_DTL_MAX_BACK_OFF_TIME)
            else:
                logger.error()
                raise TimeoutError(
                    f'No bulk search result after waiting {self.OCD_DTL_MAX_BULK_SEARCH_TIME / 60:.0f} mins\n'
                    f'task_uuid: "{task_uuid}"'
                )

        return json_response

    def get_threats(self, query_hash: str, query_fields: List[str] = None) -> dict:
        body = {
            "query_hash": query_hash,
            "query_fields": query_fields
        }
        response = self.datalake_requests(self.url, 'post', post_body=body, headers=self._post_headers())
        if not response:
            logger.error('No bulk search created, is the query_hash valid as well as the query_fields ?')
            return {}
        return self._handle_bulk_search_task(task_uuid=response['task_uuid'])
