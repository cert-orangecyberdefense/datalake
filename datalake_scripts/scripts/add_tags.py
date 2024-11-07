import sys

from datalake import Datalake
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import (
    save_output,
    retrieve_hashkeys_from_file,
)


def post_tags(hashkeys, tags, public, dtl):
    return_value = []
    for hashkey in hashkeys:
        try:
            dtl.Tags.add_to_threat(hashkey, tags, public)
        except ValueError as e:
            dtl.logger.warning("\x1b[6;30;41m" + hashkey + ": FAILED\x1b[0m")
            dtl.logger.debug(
                "\x1b[6;30;41m" + hashkey + ": FAILED : " + str(e) + "\x1b[0m"
            )
            return_value.append(hashkey + ": FAILED")
        else:
            return_value.append(hashkey + ": OK")
            dtl.logger.info("\x1b[6;30;42m" + hashkey + ": OK\x1b[0m")
    return return_value


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    parser = BaseScripts.start("Add tags to a specified list of hashkeys.")
    parser.add_argument(
        "hashkeys",
        help="hashkeys of the threat to add tags",
        nargs="*",
    )
    parser.add_argument(
        "-i",
        "--input",
        help="hashkey txt file, with one hashkey by line",
    )
    parser.add_argument(
        "-p",
        "--public",
        help="set the visibility to public. Default is organization",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--tag",
        nargs="+",
        help="add a list of tags",
        required=True,
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    if not args.hashkeys and not args.input:
        parser.error("either a hashkey or an input (file) is required")

    hashkeys = list(args.hashkeys) if args.hashkeys else []

    if args.input:
        retrieve_hashkeys_from_file(args.input, hashkeys)

    dtl = Datalake(env=args.env, log_level=args.loglevel)
    response = post_tags(hashkeys, args.tag, args.public, dtl)

    if args.output:
        save_output(args.output, response)
        dtl.logger.debug(f"Results saved in {args.output}\n")
    dtl.logger.debug(f"END: add_tags.py")


if __name__ == "__main__":
    sys.exit(main())
