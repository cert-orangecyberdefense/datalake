import sys
import json
from collections import OrderedDict
from datalake import ThreatType, OverrideType
from datalake import Datalake
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import (
    save_output,
    parse_threat_types,
    split_list,
    flatten_list,
    retrieve_hashkeys_from_file,
)


def get_whitelist_threat_types():
    return [{"threat_type": threat_type, "score": 0} for threat_type in ThreatType]


def main(override_args=None):
    """Method to start the script"""
    # Load initial args
    parser = BaseScripts.start("Edit scores of a specified list of ids (hashkeys)")
    parser.add_argument(
        "hashkeys",
        help="hashkeys of the threat to edit score.",
        nargs="*",
    )
    parser.add_argument(
        "-i",
        "--input",
        help="hashkey txt file, with one hashkey by line.",
    )
    parser.add_argument(
        "-tt",
        "--threat-types",
        nargs="+",
        help="choose specific threat types and their score, like: ddos 50 scam 15",
        default=[],
        action="append",
    )
    parser.add_argument(
        "-w",
        "--whitelist",
        help="Whitelist the input, equivalent to setting all threat types at 0.",
        action="store_true",
    )
    parser.add_argument(
        "--lock",
        help="""sets override_type to lock. Scores won't be updated by the algorithm for three months. Newer IOCs with override_type lock can still override old lock changes.
            temporary: all values should override any values provided by older IOCs,
            but not newer ones.
            Default is "temporary" (all values should override any values provided by older IOCs)""",
        action="store_true",
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    dtl.logger.debug(f"START: edit_score.py")

    if not args.hashkeys and not args.input:
        parser.error("either a hashkey or an input file is required")

    if args.lock:
        override_type = OverrideType.LOCK
    else:
        override_type = OverrideType.TEMPORARY

    if args.whitelist:
        parsed_threat_type = get_whitelist_threat_types()
    else:
        args.threat_types = flatten_list(args.threat_types)
        if not args.threat_types or len(args.threat_types) % 2 != 0:
            parser.error("threat_types invalid ! should be like: ddos 50 scam 15")
        parsed_threat_type = parse_threat_types(args.threat_types)
    # removing duplicates while preserving order
    hashkeys = list(OrderedDict.fromkeys(args.hashkeys)) if args.hashkeys else []
    if args.input:
        retrieve_hashkeys_from_file(args.input, hashkeys)
        if not hashkeys:
            raise parser.error("No hashkey found in the input file.")
    hashkeys_chunks = list(split_list(hashkeys, 100))

    response_list = []
    for index, hashkeys in enumerate(hashkeys_chunks):
        try:
            dtl.Threats.edit_score_by_hashkeys(
                hashkeys, parsed_threat_type, override_type
            )
        except ValueError as e:
            dtl.logger.warning(
                f"\x1b[6;30;41mBATCH {str(index+1)}/{len(list(hashkeys_chunks))}: FAILED\x1b[0m"
            )
            for hashkey in hashkeys:
                response_list.append(hashkey + ": FAILED")
                dtl.logger.warning(f"\x1b[6;30;41m{hashkey} : FAILED\x1b[0m")
            dtl.logger.error(e)
        else:
            dtl.logger.info(
                f"\x1b[6;30;42mBATCH {str(index+1)}/{len(list(hashkeys_chunks))}: OK\x1b[0m"
            )
            for hashkey in hashkeys:
                response_list.append(hashkey + ": OK")

    if args.output:
        save_output(args.output, response_list)
        dtl.logger.info(f"Results saved in {args.output}\n")
    dtl.logger.debug(f"END: edit_score.py")


if __name__ == "__main__":
    sys.exit(main())
