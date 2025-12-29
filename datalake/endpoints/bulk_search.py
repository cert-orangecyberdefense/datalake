from http.client import ResponseNotReady

from requests import Response

from datalake import BulkSearchNotFound
from datalake.common.bulk_search_task import BulkSearchTask
from datalake.common.output import parse_response, Output, output_supported
from datalake.endpoints import Endpoint


class BulkSearch(Endpoint):
    def create_task(
        self,
        for_stix_export: bool = False,
        query_body: dict = None,
        query_hash: str = None,
        query_fields: list = None,
        indicators_only: bool = None,
        indicators_and_threat_entities_only: bool = None,
    ) -> BulkSearchTask:
        """Creates a bulk search task"""
        if not query_body and not query_hash:
            raise ValueError("Either a query_body or query_hash is required")

        body = {"query_fields": query_fields} if query_fields else {}
        if query_body:
            body["query_body"] = query_body
        else:
            body["query_hash"] = query_hash
        if for_stix_export:
            body["for_stix_export"] = for_stix_export
        if indicators_only:
            body["indicators_only"] = indicators_only
        if indicators_and_threat_entities_only:
            body["indicators_and_threat_entities_only"] = (
                indicators_and_threat_entities_only
            )

        url = self._build_url_for_endpoint("bulk-search")
        response = self.datalake_requests(
            url, "post", post_body=body, headers=self._post_headers()
        ).json()
        return self.get_task(response["task_uuid"])

    def get_task(self, task_uuid) -> BulkSearchTask:
        url = self._build_url_for_endpoint("bulk-search-tasks")
        body = {"task_uuid": task_uuid}
        response = self.datalake_requests(
            url, "post", post_body=body, headers=self._post_headers()
        ).json()
        results = response["results"]
        if len(results) != 1:
            raise BulkSearchNotFound
        bs_as_json = results[0]
        return BulkSearchTask(endpoint=self, **bs_as_json)

    @output_supported(
        {
            Output.JSON,
            Output.JSON_ZIP,
            Output.STIX_ZIP,
            Output.CSV,
            Output.CSV_ZIP,
        }
    )
    def download(self, task_uuid, output=Output.JSON, stream=False):
        """
        Download the bulk search task with the given uuid.
        Stream parameter enables the raw stream to be returned, allowing it to be processed by chunks.
        """
        url = self._build_url_for_endpoint("bulk-search-task")
        url = url.format(task_uuid=task_uuid)
        response: Response = self.datalake_requests(
            url, "get", headers=self._get_headers(output=output), stream=stream
        )
        if response.status_code == 202:
            raise ResponseNotReady(response.json().get("message", ""))
        if stream:
            return response  # Return the raw response
        return parse_response(response)
