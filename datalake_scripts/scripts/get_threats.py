import sys

from datalake import Datalake
from datalake.common.logger import logger, configure_logging
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import load_list, save_output


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    parser = BaseScripts.start(
        "Retrieve threats (as Json) from a list of ids (hashkeys)"
    )
    parser.add_argument(
        "hashkeys",
        help="hashkeys of the threats to retreive",
        nargs="*",
    )
    parser.add_argument(
        "-i",
        "--input",
        help="list of threats ids (hashkeys) that need to be retrieved",
    )
    parser.add_argument(
        "--lost",
        help="file path to save hashkeys that were not found into",
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    dtl.logger.debug(f"START: get_threats.py")

    if not args.hashkeys and not args.input:
        parser.error("either a hashkey or an input (file) is required")
    threats_list = load_list(args.input) if args.input else args.hashkeys
    dtl.logger.debug(f"TOTAL: {len(threats_list)} threats in parameters")

    list_threats, list_not_found_hashkeys = dtl.Threats.get_threats_with_comments(
        threats_list
    )

    if args.output:
        save_output(args.output, list_threats)
        dtl.logger.debug(f"Threats JSON saved in {args.output}\n")
    if args.lost:
        save_output(args.lost, list_not_found_hashkeys)
        dtl.logger.debug(f"Threats not found saved in {args.lost}\n")
    dtl.logger.debug(f"END: get_threats.py")


if __name__ == "__main__":
    sys.exit(main())
