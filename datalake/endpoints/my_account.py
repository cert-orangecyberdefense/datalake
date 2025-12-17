from typing import List, Tuple

from datalake.endpoints.endpoint import Endpoint
from datalake.common.output import parse_response


class MyAccount(Endpoint):

    def me(self):
        """
        Gets details of the currently logged in user.
        """
        url = self._build_url_for_endpoint("users-me")
        response = parse_response(
            self.datalake_requests(url, "get", self._get_headers())
        )
        return response
