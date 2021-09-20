import os
from typing import List

from datalake.common.logger import logger
from datalake.endpoints import Endpoint


class BulkSearch(Endpoint):
    """
    Bulk search
    """

    def __init__(
            self,
            endpoint_config: dict,
            environment: str,
            tokens: list,
            query_body: dict = None,
            query_hash: str = None,
            query_fields: List = None,
            task_uuid: str = None,
    ):
        super().__init__(endpoint_config, environment, tokens)
        self.query_body = query_body
        self.query_fields = query_fields
        self.query_hash = query_hash
        self.task_uuid = task_uuid if task_uuid else self._create_bulk_search()
        self.properties = {"uuid": self.task_uuid}
        # self.update_status()

    OCD_DTL_MAX_BULK_SEARCH_TIME = int(os.getenv('OCD_DTL_MAX_BULK_SEARCH_TIME', 3600))

    def _build_url(self, endpoint_config: dict, environment: str):
        return self._build_url_for_endpoint('bulk-search')

    def _create_bulk_search(self):
        if not self.query_body and not self.query_hash:
            return

        body = {"query_fields": self.query_fields} if self.query_fields else {}
        if self.query_body:
            body['query_body'] = self.build_full_query_body(self.query_body)
        else:
            body['query_hash'] = self.query_hash

        url = '123'  # FIXME
        response = self.datalake_requests(url, 'post', post_body=body, headers=self._post_headers())
        if not response:
            logger.error('No bulk search created, is the query_hash valid as well as the query_fields ?')
            return {}
        return response['task_uuid']

    def download_results(self):
        if not self.query_body and not self.query_hash:
            raise ValueError(f'you must provide query_hash or query_body !!!')

        body = {"query_fields": self.query_fields} if self.query_fields else {}
        if self.query_body:
            body['query_body'] = self.build_full_query_body(self.query_body)
        else:
            body['query_hash'] = self.query_hash

        bulk_results_url = self._build_url_for_endpoint('retrieve-bulk-search')
        response = self.datalake_requests(bulk_results_url, 'post', post_body=body, headers=self._post_headers())
        if not response:
            logger.error('No bulk search created, is the query_hash valid as well as the query_fields ?')
            return {}
        return response

    def update_status(self):
        ''' to be done'''
        pass

    def get_query_hash(self):
        return self.properties.get('advanced_query_hash')

    def get_bulk_search_hash(self):
        return self.properties.get('bulk_search_hash')

    def get_state(self):
        return self.properties.get('state')

    def get_resultCount(self):
        return self.properties.get('results')

    def get_user(self):
        return self.properties.get('user')

    def get_timestamps(self):
        timestamps = {
            "created_at": self.properties.get('created_at'),
            "file_delete_after": self.properties.get('file_delete_after'),
            "finished_at": self.properties.get('finished_at'),
            "started_at": self.properties.get('started_at'),
            "eta": self.properties.get('eta')
        }
        return timestamps
