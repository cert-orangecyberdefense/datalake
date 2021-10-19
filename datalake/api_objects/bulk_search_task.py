import asyncio
import datetime
import os
from enum import Enum

from datalake.common.ouput import Output
from datalake.common.utils import parse_api_timestamp


class BulkSearchTaskState(Enum):
    NEW = 'NEW'
    QUEUED = 'QUEUED'
    IN_PROGRESS = 'IN_PROGRESS'
    DONE = 'DONE'
    CANCELLED = 'CANCELLED'
    FAILED_ERROR = 'FAILED_ERROR'
    FAILED_TIMEOUT = 'FAILED_TIMEOUT'


BULK_SEARCH_FAILED_STATE = {
    BulkSearchTaskState.CANCELLED,
    BulkSearchTaskState.FAILED_TIMEOUT,
    BulkSearchTaskState.FAILED_ERROR
}


class BulkSearchFailedError(Exception):
    def __init__(self, failed_state: BulkSearchTaskState):
        self.failed_state = failed_state


class BulkSearchNotFound(Exception):
    pass


class BulkSearchTask:
    """
    Bulk Search Task as represented by the API

    This class is a thin wrapper around information returned by the API
    """

    REQUEST_INTERVAL = float(os.getenv('OCD_DTL_MAX_BACK_OFF_TIME', 10))

    def __init__(
            self,
            endpoint: "BulkSearch",
            bulk_search: dict,
            bulk_search_hash: str,
            created_at: str,
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
        """Do not call this method directly, use BulkSearch.create_task instead"""
        self._endpoint = endpoint
        # flatten bulk_search field
        self.advanced_query_hash = bulk_search['advanced_query_hash']
        self.query_fields = bulk_search['query_fields']
        self.bulk_search_hash = bulk_search_hash
        self.created_at = parse_api_timestamp(created_at)
        self.eta = parse_api_timestamp(eta)
        self.file_delete_after = file_delete_after
        self.file_deleted = file_deleted
        self.file_size = file_size
        self.finished_at = parse_api_timestamp(finished_at)
        self.progress = progress
        self.queue_position = queue_position
        self.results = results
        self.started_at = parse_api_timestamp(started_at)
        self.state = BulkSearchTaskState[state]
        self.user = user
        self.uuid = uuid

    def download(self, output=Output.JSON):
        """
        Download a bulk search task, if it is not ready to be downloaded, it'll return a ResponseNotReady error

        Use download_sync/download_async to automatically wait for the bulk search to be ready before downloading it
        """
        return self._endpoint.download(self.uuid, output=output)

    async def download_async(self, output=Output.JSON, timeout=15 * 60):
        """
        Wait asynchronously for the bulk search to be ready then return its result

        Note that the requests library is used which is blocking.
        timeout parameter is in seconds.
        """
        start = datetime.datetime.utcnow()
        while self.state != BulkSearchTaskState.DONE:
            if self.state in BULK_SEARCH_FAILED_STATE:
                raise BulkSearchFailedError(self.state)
            time_passed = datetime.datetime.utcnow() - start
            if time_passed.total_seconds() > timeout:
                raise TimeoutError()

            await asyncio.sleep(self.REQUEST_INTERVAL)
            self.update()
        return self.download(output=output)

    def download_sync(self, output=Output.JSON, timeout=15 * 60):
        """Blocking version of download_async, easier to use but doesn't allow parallelization"""
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.download_async(output, timeout))

    def update(self):
        """Query the API to refresh the tasks attributes"""
        updated_bs = self._endpoint.get_task(self.uuid)
        self.__dict__.update(updated_bs.__dict__)  # Avoid to return a new object
