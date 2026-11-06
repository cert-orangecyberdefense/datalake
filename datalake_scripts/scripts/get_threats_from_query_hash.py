import json
import os
import sys

from datalake import Datalake
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.rendering import get_renderer
from datalake_scripts.helper_scripts.output_builder import format_threats_output


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    parser = BaseScripts.start("Retrieve a list of response from a given query hash.")
    parser.add_argument(
        "--query-fields",
        help="fields to be retrieved from the threat (default: only the hashkey)\n"
        "If an atom detail isn't present in a particular atom, empty string is returned.",
        nargs="+",
        default=["threat_hashkey"],
    )
    parser.add_argument(
        "--list",
        help="Turn the output in a list (require query_fields to be a single element)",
        action="store_true",
    )
    required_named = parser.add_argument_group("required arguments")
    required_named.add_argument(
        "query_hash",
        help="the query hash from which to retrieve the response hashkeys or a path to the query body json file",
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)
    dtl.logger.debug(f"START: get_threats_from_query_hash.py")

    if len(args.query_fields) > 1 and args.list:
        parser.error(
            "List output format is only available if a single element is queried (via query_fields)"
        )

    query_body = {}
    query_hash = args.query_hash
    if len(query_hash) != 32 or os.path.exists(query_hash):
        try:
            with open(query_hash, "r") as query_body_file:
                query_body = json.load(query_body_file)
        except FileNotFoundError:
            dtl.logger.error(
                f"Couldn't understand the given value as a query hash or path to query body: {query_hash}"
            )
            exit(1)

    dtl.logger.debug(f"Start to search for threat from the query hash:{query_hash}")
    renderer = get_renderer(dtl)
    with renderer.progress("Creating bulk task") as progress:
        task = dtl.BulkSearch.create_task(
            query_body=query_body,
            query_hash=query_hash,
            query_fields=args.query_fields,
        )
        progress.update(f"Waiting for bulk task {task.uuid} response")
        response = task.download_sync()
    original_count = response.get("count", 0)
    dtl.logger.info(f"Number of threat that have been retrieved: {original_count}")

    if args.output:
        with open(args.output, "w") as output:
            output.write(format_threats_output(response, args.list))
        dtl.logger.info(f"Threats saved in {args.output}")
    else:
        renderer.threats_from_query_hash(response, one_threat_per_line=args.list)


if __name__ == "__main__":
    sys.exit(main())
