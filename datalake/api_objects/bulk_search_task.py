import asyncio
import os
from enum import Enum

from datalake.common.ouput import Output


class BulkSearchTaskState(Enum):
    NEW = 'NEW'
    QUEUED = 'QUEUED'
    IN_PROGRESS = 'IN_PROGRESS'
    DONE = 'DONE'


class BulkSearchTask:
    """
    Bulk Search Task as represented by the API

    This class is a thin wrapper around information returned by the API
    """

    OCD_DTL_MAX_BACK_OFF_TIME = float(os.getenv('OCD_DTL_MAX_BACK_OFF_TIME', 30))

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
        """Do not call this method directly, use BulkSearch.create_task instead"""
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

    def download(self, output=Output.JSON):
        """
        Download a bulk search task, if it is not ready to be downloaded, it'll return a ResponseNotReady error

        Use download_sync/download_async to automatically wait for the bulk search to be ready before downloading it
        """
        return self._endpoint.download(self.uuid, output=output)

    async def download_async(self, output=Output.JSON):  # Add warning that the request part is synchrone !
        while self.state != BulkSearchTaskState.DONE:
            # TODO Add timeout after which raise error
            # TODO handle cancelled / failled / ... error
            await asyncio.sleep(self.OCD_DTL_MAX_BACK_OFF_TIME)
            self.update()
        return self.download(output=output)  # Retry once if can't dl right away ?

    def download_sync(self, output=Output.JSON):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.download_async(output))

    def update(self):
        updated_bs = self._endpoint.get_task(self.uuid)
        self.__dict__.update(updated_bs.__dict__)  # Avoid to return a new object
