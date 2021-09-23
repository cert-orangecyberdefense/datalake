import json

from datalake.api_objects.bulk_search_task import BulkSearchTask
from datalake.common.logger import logger
from datalake.endpoints import Endpoint


class BulkSearch(Endpoint):

    def create_task(
            self,
            query_body: dict = None,
            query_hash: str = None,
            query_fields: list = None
    ) -> BulkSearchTask:
        if not query_body and not query_hash:
            raise ValueError("Either a query_body or query_hash is required")

        body = {"query_fields": query_fields} if query_fields else {}
        if query_body:
            body['query_body'] = query_body
        else:
            body['query_hash'] = query_hash

        url = self._build_url_for_endpoint('bulk-search')
        response = self.datalake_requests(url, 'post', post_body=body, headers=self._post_headers())
        return self.get_task(response['task_uuid'])

    def get_task(self, task_uuid) -> BulkSearchTask:
        url = self._build_url_for_endpoint("bulk-search-task")
        body = {"task_uuid": task_uuid}
        response = self.datalake_requests(url, 'post', post_body=body, headers=self._post_headers())
        bs_as_json = response['results'][0]  # TODO handle not found
        return BulkSearchTask(endpoint=self, **bs_as_json)

    def download(self, task_uuid):
        url = self._build_url_for_endpoint('retrieve-bulk-search')
        url = url.format(task_uuid=task_uuid)
        response = self.datalake_requests(url, 'get', headers=self._get_headers())
        # TODO handle not ready yet
        return response
