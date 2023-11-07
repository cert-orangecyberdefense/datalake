from datalake.endpoints.endpoint import Endpoint
from datalake.common.output import parse_response
import logging
import re
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class FilteredTagSubcategory(Endpoint):
    def get_filtered_and_sorted_list(
        self,
        category_name=None,
        alias=None,
        description=None,
        ids=None,
        limit=10,
        name=None,
        offset=0,
        ordering="category_name",
        stix_uuid=None,
        tag=None,
    ):
        url = self._build_url_for_endpoint("filtered-tag-subcategory")
        body = {}

        if category_name:
            body["category_name"] = category_name
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
        body["ordering"] = ordering if ordering is not None else "category_name"

        try:
            response = self.datalake_requests(
                url=url, method="post", headers=self._post_headers(), post_body=body
            )
            return parse_response(response)
        except ValueError as ve:
            error_message = str(ve)
            tag_category_match = re.search(
                r"No tag category found: ([^']+)'", error_message
            )
            if tag_category_match:
                print(
                    f"The tag category name '{tag_category_match.group(1)}' is invalid; please note that this argument is case-sensitive."
                )
            ordering_match = re.search(
                r"'([^']+)' is not a valid choice", error_message
            )
            if ordering_match:
                print(
                    f"{ordering_match.group(1)} is not a valid choice for ordering, valid values: '-category_name', '-created_at', '-name', '-updated_at', 'category_name', 'created_at', 'name', 'updated_at'"
                )
            limit_match = re.search(
                r"Must be greater than or equal to 0 and less than or equal to 5000",
                error_message,
            )
            if limit_match:
                print("The 'limit' parameter must be >= 0 and <= 5000.")
            if not tag_category_match and not ordering_match and not limit_match:
                print(
                    "An error occurred, but no specific pattern was matched in the 422 HTTP error message."
                )
            sys.exit(1)
