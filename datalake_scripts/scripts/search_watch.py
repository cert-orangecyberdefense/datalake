import sys
import logging
from datalake import Datalake
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.rendering import get_renderer
from datalake_scripts.helper_scripts.utils import load_json


def main(override_args=None):
    parser = BaseScripts.start(
        "Watch or monitor a search from given query body or query hash."
    )
    parser.add_argument("-i", "--input", help="read query body from a json file")
    parser.add_argument(
        "-qh", "--query-hash", help="sets the query hash for the search watch"
    )
    parser.add_argument(
        "-of",
        "--output-folder",
        default=".",
        help="set to the output folder to store results for search watch. Default is current folder where the script is executed",
    )
    parser.add_argument(
        "-f",
        "--filename",
        help="filename to compare with the results of actual search watch",
    )
    parser.add_argument(
        "-sdt",
        "--save-diff-threats",
        action="store_true",
        help="If set, will create a file `<queryhashkey>-diff_threats-<timestamp>.json` containing added and removed threats",
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    dtl.logger.debug(f"START: search_watch.py")

    query_body = {}
    if args.input:
        try:
            query_body = load_json(args.input)
        except ValueError as e:
            dtl.logger.error(e)
            exit(1)

    try:
        diff_threats = dtl.SearchWatch.search_watch(
            query_body=query_body,
            query_hash=args.query_hash,
            output_folder=args.output_folder,
            reference_file=args.filename,
            save_diff_threats=args.save_diff_threats,
        )
    except FileNotFoundError as e:
        if "Reference file not found" in str(e):
            dtl.logger.error(
                f"File to compare with {args.filename} does not exist check for its correct path"
            )
        elif "Error with the output folder" in str(e):
            dtl.logger.error(f"Error with the input {args.output_folder} : {e}")
        else:
            dtl.logger.error(f"An error occured : {e}")
        exit(1)

    get_renderer(dtl).search_watch_diff(diff_threats)
    dtl.logger.debug(f"END: search_watch.py")


if __name__ == "__main__":
    sys.exit(main())
