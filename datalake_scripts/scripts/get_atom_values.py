import sys

from datalake.common.config import Config
from datalake.common.logger import logger, configure_logging
from datalake.common.output import Output
from datalake.common.token_manager import TokenManager
from datalake.common.utils import (
    check_normalized_timestamp,
    convert_date_to_normalized_timestamp,
)
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.engines.get_engine import Sources
from datalake_scripts.engines.post_engine import AtomSearch
from datalake_scripts.helper_scripts.utils import load_list, save_output


def main(override_args=None):
    """Method to start the script"""
    logger.debug(f"START: get_atom_values.py")

    # Load initial args
    parser = BaseScripts.start(
        "Retrieve atom values from a list of sources ids and a time range"
    )
    parser.add_argument(
        "source_id",
        help="sources ids of the atom values to retreive",
        nargs="*",
    )
    parser.add_argument(
        "-i",
        "--input_file",
        help="list of sources ids (hashkeys) that need to be retrieved",
    )
    parser.add_argument(
        "--since",
        help="normalized timestamp (or date) to set up the start of the search of atom values",
    )
    parser.add_argument(
        "--until",
        help="normalized timestamp (or date) to set up the end of the search of atom values",
    )
    parser.add_argument(
        "-ot",
        "--output_type",
        default="json",
        help="set to the output type desired {json,csv}. Default is json if not specified",
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()
    configure_logging(args.loglevel)

    if not args.source_id and not args.input_file:
        parser.error("either a source_id or an input_file is required")
    sources_list = load_list(args.input_file) if args.input_file else args.source_id
    logger.debug(f"TOTAL: {len(sources_list)} sources found")

    if not args.since or not args.until:
        parser.error("Both timestamps since and until are required")

    # Check list of sources is not empty
    if len(sources_list) < 1:
        parser.error("At least one source id is required to perform the atom search")

    # Check given timestamps are correct
    if not check_normalized_timestamp(args.since):
        try:
            since_ts = convert_date_to_normalized_timestamp(args.since, True)
        except:
            parser.error(
                f"Since Timestamp/Date provided is incorrect : {args.since}, expected format is '%Y-%m-%dT%H:%M:%S.%f[:3]Z' or '%Y-%m-%d' "
            )
    else:
        since_ts = args.since
    if not check_normalized_timestamp(args.until):
        try:
            until_ts = convert_date_to_normalized_timestamp(args.until, False)
        except:
            parser.error(
                f"Until Timestamp/Date provided is incorrect : {args.until}, expected format is '%Y-%m-%dT%H:%M:%S.%f[:3]Z' or '%Y-%m-%d' "
            )
    else:
        until_ts = args.until

    # Load api_endpoints and tokens
    endpoint_config = Config().load_config()
    token_manager = TokenManager(endpoint_config, environment=args.env)

    # Check list of sources are valid
    engine_check_sources = Sources(endpoint_config, args.env, token_manager)
    all_sources_are_valid, list_invalid_sources = engine_check_sources.check_sources(
        sources_list
    )
    if not all_sources_are_valid:
        parser.error(f"The following sources are invalid : {list_invalid_sources}")

    search_engine_atom_values = AtomSearch(endpoint_config, args.env, token_manager)
    if not args.output_type or args.output_type == "json":
        list_atom_values = search_engine_atom_values.get_atoms(
            sources_list, since_ts, until_ts, Output.JSON
        )
    else:
        list_atom_values = search_engine_atom_values.get_atoms(
            sources_list, since_ts, until_ts, Output.CSV
        )

    if args.output:
        save_output(args.output, list_atom_values)
        logger.debug(f"Atom values saved in {args.output}\n")
    logger.debug(f"END: get_atom_values.py")


if __name__ == "__main__":
    sys.exit(main())
