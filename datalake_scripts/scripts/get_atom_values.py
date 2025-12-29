import sys

from datalake import Datalake
from datalake.common.output import Output
from datalake.common.utils import (
    check_normalized_timestamp,
    convert_date_to_normalized_timestamp,
)
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import load_list, save_output


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    parser = BaseScripts.start(
        "Retrieve atom values from a list of sources ids and a time range"
    )
    parser.add_argument(
        "sources_id",
        help="sources ids of the atom values to retreive",
        nargs="*",
    )
    parser.add_argument(
        "-i",
        "--input",
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
        "--output-type",
        default="json",
        help="set to the output type desired {json,csv}. Default is json if not specified",
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    dtl.logger.debug(f"START: get_atom_values.py")

    if not args.sources_id and not args.input:
        parser.error("either a list of sources_id or an input (file) is required")
    sources_list = load_list(args.input) if args.input else args.sources_id
    dtl.logger.debug(f"TOTAL: {len(sources_list)} sources found")

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

    output_type = (
        Output.JSON if (not args.output_type or args.output_type) else Output.CSV
    )

    try:
        # Checking if sources are valid is done in atom_values method
        list_atom_values = dtl.Threats.atom_values(
            sources_list, since_ts, until_ts, output_type
        )
    except ValueError as e:
        dtl.logger.error(e)
        list_atom_values = None

    if args.output and list_atom_values:
        save_output(args.output, list_atom_values)
        dtl.logger.debug(f"Atom values saved in {args.output}\n")
    dtl.logger.debug(f"END: get_atom_values.py")


if __name__ == "__main__":
    sys.exit(main())
