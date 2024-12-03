import os
from typing import List, Union, Dict
from time import time, sleep

from requests.sessions import PreparedRequest

from datalake import AtomType, ThreatType, OverrideType, Atom
from datalake.common.token_manager import TokenManager
from datalake.common.atom import ScoreMap
from datalake.common.output import Output, output_supported, parse_response
from datalake.common.utils import (
    split_list,
    aggregate_csv_or_json_api_response,
    save_output,
    check_normalized_timestamp,
)
from datalake.endpoints.endpoint import Endpoint


class Threats(Endpoint):
    _NB_ATOMS_PER_BULK_LOOKUP = 100
    OCD_DTL_MAX_BULK_THREATS_TIME = int(os.getenv("OCD_DTL_MAX_BULK_THREATS_TIME", 600))
    OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT = int(
        os.getenv("OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT", 10)
    )
    OCD_DTL_MAX_BACK_OFF_TIME = float(os.getenv("OCD_DTL_MAX_BACK_OFF_TIME", 30))
    OCD_DTL_MAX_EDIT_SCORE_HASHKEYS = int(
        os.getenv("OCD_DTL_MAX_EDIT_SCORE_HASHKEYS", 100)
    )

    def __init__(
        self,
        logger,
        endpoint_config: dict,
        environment: str,
        token_manager: TokenManager,
        sources_instance,  # Sources class
        proxies: dict = None,
        verify: bool = True,
    ):
        super().__init__(
            logger, endpoint_config, environment, token_manager, proxies, verify
        )
        self.sources_instance = sources_instance  # Store the Sources instance

    def _bulk_lookup_batch(
        self,
        atom_values: list,
        atom_type: AtomType = None,
        hashkey_only=False,
        output=Output.JSON,
        return_search_hashkey=False,
    ) -> dict:
        """Bulk lookup done on maximum _NB_ATOMS_PER_BULK_LOOKUP atoms"""
        typed_atoms = {}
        if not atom_type:
            atoms_values_extractor_response = self._atom_values_extract(atom_values)
            if atoms_values_extractor_response["found"] > 0:
                typed_atoms = atoms_values_extractor_response["results"]
            else:
                raise ValueError("none of your atoms could be typed")
        elif not isinstance(atom_type, AtomType):
            raise ValueError(f"{atom_type} atom_type could not be treated")
        else:
            typed_atoms[atom_type.value] = atom_values

        body: dict = typed_atoms
        body["hashkey_only"] = hashkey_only
        body["return_search_hashkey"] = return_search_hashkey
        url = self._build_url_for_endpoint("threats-bulk-lookup")
        response = self.datalake_requests(
            url, "post", self._post_headers(output=output), body
        )
        return parse_response(response)

    @output_supported({Output.JSON, Output.CSV})
    def bulk_lookup(
        self,
        atom_values: list,
        atom_type: AtomType = None,
        hashkey_only=False,
        output=Output.JSON,
        return_search_hashkey=False,
    ) -> Union[dict, str]:
        """
        Look up multiple threats at once in the API, returning :
        - their hashkeys
        - atom_values
        - the search_phrase used
        - a boolean indicating if atom_value is present as a threat in Datalake
        - a boolean indicating if you have access to the threat in Datalake
        - additionnal fields are also returned if haskey_only is not enabled

        Compared to the lookup endpoint, it allow to lookup big batch of values faster as fewer API calls are made.
        However, fewer outputs types are supported as of now.
        """
        aggregated_response = [] if output is Output.CSV else {}
        search_hashkey_list = []
        for atom_values_batch in split_list(
            atom_values, self._NB_ATOMS_PER_BULK_LOOKUP
        ):
            batch_result = self._bulk_lookup_batch(
                atom_values_batch,
                atom_type,
                hashkey_only,
                output,
                return_search_hashkey,
            )
            if "search_hashkey" in batch_result:
                search_hashkey_list.append(batch_result.pop("search_hashkey"))
            aggregated_response = aggregate_csv_or_json_api_response(
                aggregated_response,
                batch_result,
            )
        if search_hashkey_list:
            aggregated_response["search_hashkey"] = search_hashkey_list
        if output is Output.CSV:
            aggregated_response = "\n".join(
                aggregated_response
            )  # a string is expected for CSV output
        return aggregated_response

    @output_supported({Output.JSON, Output.CSV, Output.MISP, Output.STIX})
    def lookup(
        self,
        atom_value,
        atom_type: AtomType = None,
        hashkey_only=False,
        output=Output.JSON,
    ) -> dict:
        """
        Look up a threat in the API, returning its id (called threat's hashkey) and if it is present in Datalake.

        The hashkey is also based on the threat type.
        If atom_type is not specified, another query to the API will be made to determine it.
        With hashkey_only = False, the full threat details are returned in the requested format.
        """
        atom_type_str = None
        if not atom_type:
            threats = [atom_value]
            atoms_values_extractor_response = self._atom_values_extract(threats)
            if atoms_values_extractor_response["found"] > 0:
                atom_type_str = list(atoms_values_extractor_response["results"].keys())[
                    0
                ]
            else:
                raise ValueError("atom could not be typed")
        elif not isinstance(atom_type, AtomType):
            raise ValueError(f"{atom_type} atom_type could not be treated")
        else:  # atom_type is a valid enum passed by the user
            atom_type_str = atom_type.value

        url = self._build_url_for_endpoint("threats-lookup")
        params = {
            "atom_value": atom_value,
            "atom_type": atom_type_str,
            "hashkey_only": hashkey_only,
        }
        req = PreparedRequest()
        req.prepare_url(url, params)
        response = self.datalake_requests(
            req.url, "get", self._get_headers(output=output)
        )
        return parse_response(response)

    def _atom_values_extract(
        self, untyped_atoms: List[str], treat_hashes_like=AtomType.FILE
    ) -> dict:
        """
        Determines the types of atoms passed.

        values that are believed to be hashes will be returned as the AtomType provided in <treat_hashes_like>
        """
        url = self._build_url_for_endpoint("threats-atom-values-extract")
        payload = {
            "content": " ".join(untyped_atoms),
            "treat_hashes_like": treat_hashes_like.value,
        }
        return self.datalake_requests(url, "post", self._post_headers(), payload).json()

    def edit_score_by_hashkeys(
        self,
        hashkeys,
        scores_list,
        override_type: OverrideType = OverrideType.TEMPORARY,
    ):
        """
        Edit the score of a list of threats using the API. Default is 100. This function will receive a list of
        hashkey to edit, a list of dictionaries defining the scores to set and an override type. Can only process a
        limited number of hashkeys at one time. Can be modified with the environment variable
        OCD_DTL_MAX_EDIT_SCORE_HASHKEYS.
        """
        if type(hashkeys) is not list or not hashkeys:
            raise ValueError("Hashkeys has to be a list of string")
        if len(hashkeys) > self.OCD_DTL_MAX_EDIT_SCORE_HASHKEYS:
            raise ValueError(
                f"Can't process more than {self.OCD_DTL_MAX_EDIT_SCORE_HASHKEYS} hashkeys at one time."
            )
        if any(type(hashkey) is not str or not hashkey for hashkey in hashkeys):
            raise ValueError("Hashkeys has to be a list of string")
        if not isinstance(override_type, OverrideType):
            raise ValueError("Invalid OverrideType input")
        req_body = {
            "override_type": override_type.value,
            "hashkeys": hashkeys,
            "scores": self._build_scores(scores_list),
        }
        url = self._build_url_for_endpoint("threats-bulk-scoring-edits")
        response = self.datalake_requests(url, "post", self._post_headers(), req_body)
        return parse_response(response)

    def edit_score_by_query_body_hash(
        self,
        query_body_hash: str,
        scores_list: List[ScoreMap],
        override_type: OverrideType = OverrideType.TEMPORARY,
    ):
        """
        Edit the score of a list of threats using the API.
        This function will receive a query body hash,
        a list of dictonaries defining the scores to set and an override type.
        """
        if not isinstance(override_type, OverrideType):
            raise ValueError("Invalid OverrideType input")
        req_body = {
            "override_type": override_type.value,
            "query_body_hash": query_body_hash,
            "scores": self._build_scores(scores_list),
        }
        url = self._build_url_for_endpoint("threats-bulk-scoring-edits")
        response = self.datalake_requests(url, "post", self._post_headers(), req_body)
        return parse_response(response)

    @staticmethod
    def _build_scores(scores_list: List[ScoreMap]):
        scores_body = []
        for score_dict in scores_list:
            if not isinstance(score_dict["threat_type"], ThreatType):
                raise ValueError("Invalid threat_type input")
            if score_dict["score"] > 100 or score_dict["score"] < 0:
                raise ValueError("Invalid score input, min: 0, max: 100")

            scores_body.append(
                {
                    "score": {"risk": score_dict["score"]},
                    "threat_type": score_dict["threat_type"].value,
                }
            )
        return scores_body

    @staticmethod
    def _build_whitelist_scores():
        scores = []
        for threat in ThreatType:
            scores.append({"score": {"risk": 0}, "threat_type": threat.value})
        return scores

    def add_threats(
        self,
        atom_list: List[str],
        atom_type: AtomType,
        threat_types: List[ScoreMap] = None,
        override_type: OverrideType = OverrideType.TEMPORARY,
        whitelist: bool = False,
        public: bool = True,
        tags: List = None,
        external_analysis_link: List = None,
    ):
        """
        Add a list of threats to datalake using the API.
        The type of atom provided in the list of threats to add need to be the same, for example a list of IPs.
        """
        self._check_add_threats_params(
            atom_list, override_type, threat_types, whitelist
        )
        tags = tags or []  # API requires a tag field, default to an empty list
        payload = {"override_type": override_type.value, "public": public}
        if whitelist:
            scores = self._build_whitelist_scores()
        else:
            scores = self._build_scores(threat_types)
        return self._bulk_add_threat(
            atom_list, atom_type, payload, tags, scores, external_analysis_link
        )

    @staticmethod
    def _check_add_threats_params(atom_list, override_type, threat_types, whitelist):
        if not threat_types and not whitelist:
            raise ValueError(
                "threat_types is required if the atom is not for whitelisting"
            )
        if not isinstance(override_type, OverrideType):
            raise ValueError("Invalid OverrideType input")
        if any(len(atom) < 1 for atom in atom_list):
            raise ValueError("Empty atom in atom_list")

    def _bulk_add_threat(
        self,
        atom_list: List,
        atom_type: AtomType,
        payload: Dict,
        tags: List,
        scores: List[Dict],
        external_analysis_link: List = None,
    ):
        url = self._build_url_for_endpoint("bulk-manual-threats")
        payload["atom_type"] = atom_type.value
        payload["scores"] = scores
        payload["tags"] = tags
        if external_analysis_link:
            payload["threat_data"] = {
                "content": {
                    f"{atom_type.value}_content": {
                        "external_analysis_link": external_analysis_link
                    }
                }
            }
        hashkey_created = self._queue_bulk_threats(atom_list, payload, url)
        return hashkey_created

    def _queue_bulk_threats(self, atom_list, payload, url):
        """Creates the manual bulk tasks to add threats then checks if those sucessfully created suceeded"""
        bulk_response = []
        bulk_in_flight = []  # bulk task uuid unchecked
        failed_batch = []
        for batch in split_list(atom_list, 100):
            if len(bulk_in_flight) >= self.OCD_DTL_MAX_BULK_THREATS_IN_FLIGHT:
                bulk_threat_task_uuid = bulk_in_flight.pop(0)
                bulk_response.append(
                    self._check_bulk_threats_added(bulk_threat_task_uuid)
                )

            payload["atom_values"] = "\n".join(batch)  # Raw csv expected
            response = self.datalake_requests(
                url, "post", self._post_headers(), payload
            )
            self.logger.debug(f"_queue_bulk_threats, response : {str(response)}")
            response = parse_response(response)
            self.logger.debug(f"_queue_bulk_threats, response parsed : {str(response)}")
            task_uid = response.get("task_uuid")
            if task_uid:
                bulk_in_flight.append(response["task_uuid"])
            else:
                failed_batch.append(batch)
        if failed_batch:
            bulk_response.append(
                {
                    "success": {"created_hashkeys": [], "created_atom_values": []},
                    "failed": {
                        "failed_hashkeys": [],
                        "failed_atom_values": failed_batch,
                    },
                }
            )

        # Finish to check the other bulk tasks
        for bulk_threat_task_uuid in bulk_in_flight:
            bulk_response.append(self._check_bulk_threats_added(bulk_threat_task_uuid))
        return bulk_response

    def _check_bulk_threats_added(self, bulk_threat_task_uuid) -> dict:
        """Check if the bulk manual threat submission completed successfully and if so return the hashkeys created"""
        success = []
        failed = []
        url = self._build_url_for_endpoint("bulk-manual-threats-task")

        try:
            response = self._handle_bulk_task(
                bulk_threat_task_uuid,
                url,
                timeout=self.OCD_DTL_MAX_BULK_THREATS_TIME,
            )
        except TimeoutError:
            response = {}

        hashkeys = response.get("hashkeys")
        atom_values = response.get("atom_values")
        if hashkeys and response.get("state", "CANCELLED") == "DONE":
            hashkey_created = []
            atom_val_created = []
            for hashkey in hashkeys:
                hashkey_created.append(hashkey)
            for atom_value in atom_values:
                atom_val_created.append(atom_value)
            success.append(
                {
                    "created_hashkeys": hashkey_created,
                    "created_atom_values": atom_val_created,
                }
            )
        else:  # if the state is not DONE we consider the batch a failure
            # default values in case the json is missing some fields
            hashkeys = hashkeys or ["<missing value>"]
            atom_values = atom_values or ["<missing value>"]
            failed.append(
                {"failed_hashkeys": hashkeys, "failed_atom_values": atom_values}
            )
        response_dict = {"success": success, "failed": failed}
        return response_dict

    def _handle_bulk_task(self, task_uuid, retrieve_bulk_result_url, timeout):
        retrieve_bulk_result_url = retrieve_bulk_result_url.format(task_uuid=task_uuid)
        start_time = time()
        back_off_time = 1
        json_response = None
        while not json_response:
            response = self.datalake_requests(
                retrieve_bulk_result_url, "get", self._get_headers()
            )
            if response.status_code == 200:
                potential_json_response = response.json()
                if not potential_json_response["state"] in ("DONE", "CANCELLED"):
                    continue
                json_response = response.json()
            elif time() - start_time + back_off_time < timeout:
                sleep(back_off_time)
                back_off_time = min(back_off_time * 2, self.OCD_DTL_MAX_BACK_OFF_TIME)
            else:
                raise TimeoutError(
                    f"No bulk result after waiting {timeout / 60:.0f} mins\n"
                    f'task_uuid: "{task_uuid}"'
                )
        return json_response

    @staticmethod
    def _check_add_threat_params(atom, override_type, threat_types, whitelist):
        if not threat_types and not whitelist:
            raise ValueError(
                "threat_types is required if the atom is not for whitelisting"
            )
        if not isinstance(override_type, OverrideType):
            raise ValueError("Invalid OverrideType input")
        if type(atom) == Atom or not isinstance(atom, Atom):
            raise TypeError("atom needs to be an Atom subclasses.")

    def add_threat(
        self,
        atom: Atom,
        threat_types: List[ScoreMap] = None,
        override_type: OverrideType = OverrideType.TEMPORARY,
        whitelist: bool = False,
        public: bool = True,
        tags: List = None,
    ):
        """
        Add a single threat to datalake using the API.
        This method is slower than add_threats for submitting a large number of threats but allows to provide greater details
        """
        self._check_add_threat_params(atom, override_type, threat_types, whitelist)
        tags = tags or []  # API requires a tag field, default to an empty list
        if whitelist:
            scores = self._build_whitelist_scores()
        else:
            scores = self._build_scores(threat_types)
        payload = {
            "override_type": override_type.value,
            "public": public,
            "threat_data": {
                "scores": scores,
                "tags": tags,
                "content": atom.generate_atom_json(),
            },
        }
        url = self._build_url_for_endpoint("threats-manual")
        response = self.datalake_requests(url, "post", self._post_headers(), payload)
        return parse_response(response)

    @staticmethod
    def _check_atom_values_params(
        source_id,
        normalized_timestamp_since,
        normalized_timestamp_until,
        output,
        output_path,
    ):
        if not source_id or len(source_id) < 1:
            raise ValueError("A list of minimum one source id required")
        if not normalized_timestamp_since or not normalized_timestamp_until:
            raise ValueError("Both timestamps parameters are required")
        if not check_normalized_timestamp(normalized_timestamp_since):
            raise ValueError("Invalid normalized_timestamp_since format")
        if not check_normalized_timestamp(normalized_timestamp_until):
            raise ValueError("Invalid normalized_timestamp_until format")
        if output != Output.JSON and output != Output.CSV:
            raise TypeError("output needs to either be set to JSON or CSV")

    def atom_values(
        self,
        source_id: List = None,
        normalized_timestamp_since: str = None,
        normalized_timestamp_until: str = None,
        output: Output = Output.JSON,
        output_path: str = None,
    ):
        """
        Get all atom values based on given source id list and from time range.
        """
        self._check_atom_values_params(
            source_id,
            normalized_timestamp_since,
            normalized_timestamp_until,
            output,
            output_path,
        )

        (
            all_sources_are_valid,
            list_invalid_sources,
        ) = self.sources_instance.check_sources(source_id)
        if not all_sources_are_valid:
            raise ValueError(
                f"The following sources are invalid : {list_invalid_sources}"
            )

        payload = {
            "source_id": source_id,
            "normalized_timestamp_since": normalized_timestamp_since,
            "normalized_timestamp_until": normalized_timestamp_until,
            "ordering": ["atom_type"],
        }
        url = self._build_url_for_endpoint("atom-values")
        response = self.datalake_requests(
            url, "post", self._post_headers(output), payload
        )

        if output_path:
            save_output(output_path, parse_response(response))

        return parse_response(response)

    def _get_threat_with_comments(self, hashkey: str):
        """
        Retrieve a threat and its comments.
        Return a threat as dict
        """
        request_url = self._build_url_for_endpoint("threats").format(hashkey=hashkey)
        response = self.datalake_requests(
            request_url,
            "get",
            self._get_headers(),
            None,
        )
        threat_dict = parse_response(response)
        if threat_dict.get("hashkey"):
            request_url = self._build_url_for_endpoint("threats-comments").format(
                hashkey=hashkey
            )
            comments_dict = self.datalake_requests(
                request_url, "get", self._get_headers(), None
            )
            threat_dict["comments"] = parse_response(comments_dict)
        return threat_dict

    def get_threats_with_comments(self, hashkeys: list):
        """
        Retrieve the JSON file of a list of threats and their comments.
        Return dict containing threats found and a list of threats' hashkey not found
        """
        terminal_size = self._get_terminal_size()
        dict_threats = {"count": 0, "results": []}
        list_of_not_found_threats_hashkeys = []
        for index, hashkey in enumerate(hashkeys):
            try:
                threat_dict = self._get_threat_with_comments(hashkey)
            except Exception as e:
                self.logger.error(
                    f"Error occured for hashkey {hashkey}, error : {str(e)}"
                )
                list_of_not_found_threats_hashkeys.append(hashkey)
                continue
            if not threat_dict.get("hashkey"):
                list_of_not_found_threats_hashkeys.append(hashkey)
                self.logger.debug(
                    f"{str(index).ljust(5)}:{hashkey.ljust(terminal_size - 11)}\x1b[0;30;41mERROR\x1b[0m"
                )
            else:
                self.logger.debug(
                    f"{str(index).ljust(5)}:{hashkey.ljust(terminal_size - 10)}\x1b[0;30;42m OK \x1b[0m"
                )
                dict_threats["count"] += 1
                dict_threats["results"].append(threat_dict)
        return dict_threats, list_of_not_found_threats_hashkeys
