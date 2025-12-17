from typing import List, Tuple

from datalake.endpoints.endpoint import Endpoint
from datalake.common.output import parse_response


class Comments(Endpoint):
    def _post_comment(
        self, hashkey: str, comment: str, visibility: str = "organization"
    ) -> dict:
        """
        Post comment on threat hashkey
        """
        payload = {
            "content": comment,
            "visibility": visibility,
        }
        url = self._build_url_for_endpoint("threats-comments").format(hashkey=hashkey)
        response = self.datalake_requests(url, "post", self._post_headers(), payload)
        return parse_response(response)

    def post_comments(
        self, hashkeys: List[str], comment: str, public=True
    ) -> Tuple[list, list]:
        """
        Post same comment on one or more threats (hashkeys)
        Returns two lists: the first containing hashkeys of threats for which the comment could be added and the second when it could not
        """
        visibility = "public" if public else "organization"
        list_haskeys_comment_added = []
        list_haskeys_no_comment_added = []
        for hashkey in hashkeys:
            try:
                response = self._post_comment(hashkey, comment, visibility)
            except ValueError as e:
                self.logger.warning("\x1b[6;30;41m" + hashkey + ": FAILED\x1b[0m")
                self.logger.debug(
                    "\x1b[6;30;41m" + hashkey + ": FAILED : " + str(e) + "\x1b[0m"
                )
                list_haskeys_no_comment_added.append(hashkey)
                continue
            if not response:
                self.logger.warning(f"\x1b[6;30;41m{hashkey}: KO\x1b[0m")
                list_haskeys_no_comment_added.append(hashkey)
            else:
                list_haskeys_comment_added.append(hashkey)
                self.logger.debug(f"\x1b[6;30;42m{hashkey}: OK\x1b[0m")
        return list_haskeys_comment_added, list_haskeys_no_comment_added
