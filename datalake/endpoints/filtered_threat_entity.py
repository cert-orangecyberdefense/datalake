from datalake.endpoints.endpoint import Endpoint
from datalake.common.output import parse_response, Output, output_supported
import re
import sys


class FilteredThreatEntity(Endpoint):
    @output_supported({Output.JSON, Output.STIX})
    def get_filtered_and_sorted_list(
        self,
        threat_category_name=None,
        alias=None,
        description=None,
        ids=None,
        limit=10,
        name=None,
        offset=0,
        ordering="threat_category_name",
        stix_uuid=None,
        tag=None,
        output=Output.JSON,
    ):
        """
        Retrieve threat entities, with available filtering options as input parameters
        """
        url = self._build_url_for_endpoint("threat-entity-filtered")
        body = {}

        if threat_category_name:
            body["threat_category_name"] = threat_category_name
        if alias:
            body["alias"] = alias
        if description:
            body["description"] = description
        if ids:
            body["ids"] = ids
        if name:
            body["name"] = name
        if stix_uuid:
            body["stix_uuid"] = stix_uuid
        if tag:
            body["tag"] = tag

        # Set default values if not provided
        body["limit"] = limit if limit is not None else 10
        body["offset"] = offset if offset is not None else 0
        body["ordering"] = ordering if ordering is not None else "threat_category_name"

        try:
            response = self.datalake_requests(
                url=url,
                method="post",
                headers=self._post_headers(output=output),
                post_body=body,
            )
            return parse_response(response)
        except ValueError as ve:
            error_message = str(ve)
            threat_category_match = re.search(
                r"No threat category found: ([^']+)'", error_message
            )
            if threat_category_match:
                print(
                    f"The threat category name '{threat_category_match.group(1)}' is invalid; please note that this argument is case-sensitive."
                )
            ordering_match = re.search(
                r"'([^']+)' is not a valid choice", error_message
            )
            if ordering_match:
                print(
                    f"{ordering_match.group(1)} is not a valid choice for ordering, valid values: '-threat_category_name', '-created_at', '-name', '-updated_at', 'threat_category_name', 'created_at', 'name', 'updated_at'"
                )
            limit_match = re.search(
                r"Must be greater than or equal to 0 and less than or equal to 5000",
                error_message,
            )
            if limit_match:
                print("The 'limit' parameter must be >= 0 and <= 5000.")
            token_match = re.search(
                r"token",
                error_message,
            )
            if token_match:
                raise ve
            if (
                not threat_category_match
                and not ordering_match
                and not limit_match
                and not token_match
            ):
                print(
                    "An error occurred, but no specific pattern was matched in the 422 HTTP error message."
                )
            sys.exit(1)
