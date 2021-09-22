from enum import Enum

from datalake.common.logger import logger


class BulkSearchTaskState(Enum):
    NEW = 'NEW'
    QUEUED = 'QUEUED'
    PROGRESS = 'PROGRESS'
    DONE = 'DONE'


class BulkSearchTask:
    """
    Bulk Search Task as represented by the API

    This class is a thin wrapper around information returned by the API
    """

    # TODO replace with dataclasses when python 3.6 reach end of life
    def __init__(
            self,
            endpoint: "BulkSearch",
            bulk_search: dict,
            bulk_search_hash: str,
            created_at: str,  # TODO parse date
            eta: str,
            file_delete_after: str,
            file_deleted: bool,
            file_size: int,
            finished_at: str,
            progress: int,
            queue_position: int,
            results: int,
            started_at: str,
            state: str,
            uuid: str,
            user: dict,
    ):
        """Do not call this method directly, use BulkSearch.create_bulk_search_task instead"""
        self._endpoint = endpoint
        # flatten bulk_search field
        self.advanced_query_hash = bulk_search['advanced_query_hash']
        self.query_fields = bulk_search['query_fields']
        self.bulk_search_hash = bulk_search_hash
        self.created_at = created_at
        self.eta = eta
        self.file_delete_after = file_delete_after
        self.file_deleted = file_deleted
        self.file_size = file_size
        self.finished_at = finished_at
        self.progress = progress
        self.queue_position = queue_position
        self.results = results
        self.started_at = started_at
        self.state = BulkSearchTaskState[state]
        self.user = user
        self.uuid = uuid

    def download(self):
        ...
        # bulk_results_url = self._build_url_for_endpoint('retrieve-bulk-search')
        # response = self.datalake_requests(bulk_results_url, 'post', post_body=body, headers=self._post_headers())
        # if not response:
        #     logger.error('No bulk search created, is the query_hash valid as well as the query_fields ?')
        #     return {}
        # return response

    def update(self) -> "BulkSearchTask":
        return self._endpoint.get(self.uuid)
