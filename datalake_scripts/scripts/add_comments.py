import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.post_engine import CommentsPost


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()

    # Load initial args
    parser = starter.start('Add tags and/or comments to a specified list of hashkeys.')
    parser.add_argument(
        'hashkeys',
        help='hashkeys of the threat to add tags and/or the comment',
        nargs='*',
    )
    parser.add_argument(
        '-i',
        '--input_file',
        help='hashkey txt file, with one hashkey by line',
    )
    parser.add_argument(
        '-p',
        '--public',
        help='set the visibility to public',
        action='store_true',
    )
    parser.add_argument(
        '--comment',
        help='add the given comment',
        required=True,
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    # Load api_endpoints and tokens
    endpoint_config, main_url, tokens = starter.load_config(args)
    post_engine_add_comments = CommentsPost(endpoint_config, args.env, tokens)

    if not args.hashkeys and not args.input_file:
        parser.error("either a hashkey or an input_file is required")

    hashkeys = set(args.hashkeys) if args.hashkeys else set()
    if args.input_file:
        retrieve_hashkeys_from_file(args.input_file, hashkeys)

    response_dict = post_engine_add_comments.post_comments(
        hashkeys,
        args.comment,
        public=args.public,
    )

    if args.output:
        starter.save_output(args.output, response_dict)
        logger.debug(f'Results saved in {args.output}\n')
    logger.debug(f'END: add_comments.py')


def retrieve_hashkeys_from_file(input_file, hashkeys):
    with open(input_file, 'r') as input_file:
        for line in input_file:
            if line:
                hashkeys.add(line.strip())


if __name__ == '__main__':
    sys.exit(main())
