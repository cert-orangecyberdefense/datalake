from datalake.endpoints.endpoint import Endpoint
from datalake.common.ouput import parse_response


class Tags(Endpoint):
    def add_to_threat(
            self,
            hashkey: str,
            tags: list,
            public=False
    ):
        """
        Adds tag(s) to a threat.
        """
        if type(tags) is not list or not tags:
            raise ValueError("Tags has to be a list of string")
        if all(type(tag) is not str or not tag for tag in tags):
            raise ValueError("Tags has to be a list of string")
        
        visibility = 'public' if public else 'organization'
        tags_payload = []
        for tag in tags:
            tags_payload.append(
                {
                    'name': tag,
                    'visibility': visibility,
                }
            )
        payload = {
            'tags': tags_payload,
        }
        url = self._build_url_for_endpoint('tag').format(hashkey=hashkey)
        response = self.datalake_requests(url, 'post', self._post_headers(), payload)
        return parse_response(response)
