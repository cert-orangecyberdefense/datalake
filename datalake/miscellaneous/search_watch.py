import os
from typing import Optional
from datalake import Output
from datalake.common.utils import load_json, datetime, save_output, SetEncoder


class SearchWatch:
    def __init__(self, logger, BulkSearch):
        self.BulkSearch = BulkSearch
        self.logger = logger

    def _find_latest_json_file(self, directory_path: str) -> Optional[str]:
        """
        Find the latest json file in the directory given as argument.
        json files must have this format: `<query_hash>-<timestamp>.json`, because
        the `<timestamp>` part of the format is use to find the latest.
        Return the filename of that latest json file.
        """
        files = os.listdir(directory_path)
        json_files = [f for f in files if f.endswith(".json") and "-" in f]

        timestamps = []
        for file in json_files:
            try:
                parts = file.split("-")
                timestamp = int(parts[-1].split(".")[0])
                timestamps.append((timestamp, file))
            except (IndexError, ValueError):
                continue

        if timestamps:
            latest_file = max(timestamps, key=lambda x: x[0])[1]
            return latest_file

        return None

    def _extract_timestamp(self, filename: str) -> datetime.datetime:
        """
        The filename must be in this format: `<query_hash>-<timestamp>.json`.
        Return the datetime object of the the extracted `<timestamp>` part.
        """
        file_parts = filename.split("-")
        if len(file_parts) < 2:
            raise ValueError("Filename does not contain a valid timestamp part.")

        timestamp_str = file_parts[-1].split(".")[0]
        timestamp_int = int(timestamp_str)
        timestamp_datetime = datetime.datetime.fromtimestamp(timestamp_int)

        return timestamp_datetime

    def threats_diff(
        self,
        previous_bulk_search_output: dict,
        new_bulk_search_output: dict,
        previous_datetime: datetime,
        new_datetime: datetime,
    ) -> dict:
        """
        Takes two dictionaries (D1 and D2) which are suppose to be the result of
        two bulk search (a previous one and a new one), and two datetimes.
        Return a dictionary which contains information about `D1-D2` and `D2-D1`.
        """
        previous_threats = []
        new_threats = []

        for threat in previous_bulk_search_output["results"]:
            previous_threats.append(tuple(threat))

        for threat in new_bulk_search_output["results"]:
            new_threats.append(tuple(threat))

        previous_threats_set = set(previous_threats)
        new_threats_set = set(new_threats)

        added_threats = new_threats_set - previous_threats_set
        removed_threats = previous_threats_set - new_threats_set

        return {
            "from": previous_datetime.strftime("%Y-%m-%d %H:%M:%S"),
            "to": new_datetime.strftime("%Y-%m-%d %H:%M:%S"),
            "added": added_threats if added_threats else {},
            "removed": removed_threats if removed_threats else {},
        }

    def search_watch(
        self,
        query_body: dict = None,
        query_hash: str = None,
        output_folder: str = ".",
        reference_file: str = None,
        save_diff_threats: bool = False,
    ) -> dict:
        """
        Monitor (watch) a search to find new iocs (ones not present in your latest reference file) that match your search criteria.
        """
        if bool(query_body) == bool(query_hash):
            raise ValueError("Either a query_body or query_hash is required")

        output_type = Output.JSON
        query_fields = ["atom_value", "threat_hashkey"]

        if query_body:
            task = self.BulkSearch.create_task(
                query_body=query_body, query_fields=query_fields
            )
        else:
            task = self.BulkSearch.create_task(
                query_hash=query_hash, query_fields=query_fields
            )
        actual_datetime = datetime.datetime.now()
        bulk_search_result_json = task.download_sync(output=output_type)
        filepath = (
            output_folder
            + "/"
            + bulk_search_result_json["advanced_query_hash"]
            + "-"
            + str(int(round(datetime.datetime.timestamp(actual_datetime))))
            + ".json"
        )
        diff_threats = {}

        if reference_file:
            try:
                file_to_compare_with_data = load_json(reference_file)
            except FileNotFoundError as e:
                raise FileNotFoundError(
                    f"Reference file not found: {reference_file}"
                ) from e

            self.logger.info(
                f"\x1b[0;30;47m File to compare with {reference_file} \x1b[0m"
            )
            previous_datetime = self._extract_timestamp(reference_file)
            diff_threats = self.threats_diff(
                file_to_compare_with_data,
                bulk_search_result_json,
                previous_datetime,
                actual_datetime,
            )
        else:
            try:
                file_to_compare_with_json = self._find_latest_json_file(output_folder)
            except FileNotFoundError as e:
                raise FileNotFoundError(
                    f"Error with the output folder: {output_folder}"
                ) from e

            if file_to_compare_with_json:
                file_to_compare_with_json_path = (
                    output_folder + "/" + file_to_compare_with_json
                )
                file_to_compare_with_data = load_json(file_to_compare_with_json_path)
                self.logger.info(
                    f"\x1b[0;30;47m File to compare with {file_to_compare_with_json_path} \x1b[0m"
                )
                previous_datetime = self._extract_timestamp(file_to_compare_with_json)
                diff_threats = self.threats_diff(
                    file_to_compare_with_data,
                    bulk_search_result_json,
                    previous_datetime,
                    actual_datetime,
                )
            else:
                self.logger.info(
                    f"\x1b[0;30;43m No file to compare with {filepath} \x1b[0m"
                )

        if save_diff_threats:
            diff_threats_path = (
                output_folder
                + "/"
                + bulk_search_result_json["advanced_query_hash"]
                + "-"
                + "diff_threats"
                + "-"
                + str(int(round(datetime.datetime.timestamp(actual_datetime))))
                + ".json"
            )
            save_output(diff_threats_path, diff_threats, cls=SetEncoder)
            self.logger.info(
                f"\x1b[0;37;42m OK: DIFF THREATS SAVED IN {diff_threats_path} \x1b[0m"
            )

        save_output(filepath, bulk_search_result_json)
        self.logger.info(
            f"\x1b[0;37;42m OK: MATCHING THREATS SAVED IN {filepath} \x1b[0m"
        )

        return diff_threats
