import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.post_engine import ThreatsCommentsPost


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
        '--tag',
        nargs='+',
        help='add a list of tags',
    )
    parser.add_argument(
        '--comment',
        help='add a comment',
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    # Load api_endpoints and tokens
    endpoint_url, main_url, tokens = starter.load_config(args)
    url_threats = main_url + endpoint_url['endpoints']['threats']
    post_engine_add_comments = ThreatsCommentsPost(url_threats, main_url, tokens)

    if not args.tag and not args.comment:
        parser.error("either a tag or an argument is required")
    if not args.hashkeys and not args.input_file:
        parser.error("either a hashkey or an input_file is required")

    tag = args.tag or []
    comment = args.comment or ''  # a comment is required by the API(even empty)
    hashkeys = set(args.hashkeys) if args.hashkeys else set()

    if args.input_file:
        retrieve_hashkeys_from_file(args.input_file, hashkeys)

    response_dict = post_engine_add_comments.post_comments_and_tags_from_list(
        hashkeys,
        comment,
        tag,
        public=args.public,
    )

    if args.output:
        starter.save_output(args.output, response_dict)
        logger.debug(f'Results saved in {args.output}\n')
    logger.debug(f'END: add_new_threats.py')


def retrieve_hashkeys_from_file(input_file, hashkeys):
    with open(input_file, 'r') as input_file:
        for line in input_file:
            if line:
                hashkeys.add(line.strip())


if __name__ == '__main__':
    sys.exit(main())
