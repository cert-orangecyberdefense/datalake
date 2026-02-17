import sys

from datalake import Datalake
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import (
    save_output,
    retrieve_hashkeys_from_file,
)


def post_comments(hashkeys, comment, public, dtl):
    return_value = []
    (
        list_haskeys_comment_added,
        list_haskeys_no_comment_added,
    ) = dtl.Comments.post_comments(hashkeys, comment, public)
    for hashkey in list_haskeys_comment_added:
        return_value.append(hashkey + ": OK")
    for hashkey in list_haskeys_no_comment_added:
        return_value.append(hashkey + ": FAILED")
    return return_value


def main(override_args=None):
    """Method to start the script"""
    # Load initial args
    parser = BaseScripts.start("Add comments to a specified list of hashkeys.")
    parser.add_argument(
        "hashkeys",
        help="hashkeys of the threat to add the comment",
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
        "-c",
        "--comment",
        help="add the given comment",
        required=True,
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    if not args.hashkeys and not args.input:
        parser.error("either a hashkey or an input file is required")

    hashkeys = list(args.hashkeys) if args.hashkeys else []
    if args.input:
        retrieve_hashkeys_from_file(args.input, hashkeys)

    dtl = Datalake(env=args.env, log_level=args.loglevel)
    response = post_comments(hashkeys, args.comment, args.public, dtl)

    if args.output:
        save_output(args.output, response)
        dtl.logger.debug(f"Results saved in {args.output}\n")
    dtl.logger.debug(f"END: add_comments.py")


if __name__ == "__main__":
    sys.exit(main())
