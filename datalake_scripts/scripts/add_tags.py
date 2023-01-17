import sys

from datalake import Datalake
from datalake.common.logger import logger
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import save_output


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    parser = BaseScripts.start('Add tags and/or comments to a specified list of hashkeys.')
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
        '--tags',
        nargs='+',
        help='add a list of tags',
        required=True,
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    if not args.hashkeys and not args.input_file:
        parser.error("either a hashkey or an input_file is required")

    hashkeys = set(args.hashkeys) if args.hashkeys else set()

    if args.input_file:
        retrieve_hashkeys_from_file(args.input_file, hashkeys)

    dtl = Datalake(env=args.env, log_level=args.loglevel)
    response_dict = post_tags(
        hashkeys,
        args.tags,
        args.public,
        dtl
    )

    if args.output:
        save_output(args.output, response_dict)
        logger.debug(f'Results saved in {args.output}\n')
    logger.debug(f'END: add_tags.py')


def post_tags(hashkeys, tags, public, dtl):
    return_value = []
    for hashkey in hashkeys:
        try:
            dtl.Tags.add_to_threat(hashkey, tags, public)
        except ValueError as e:
            logger.warning('\x1b[6;30;41m' + hashkey + ': FAILED\x1b[0m')
            logger.debug('\x1b[6;30;41m' + hashkey + ': FAILED : ' + str(e) + '\x1b[0m')
            return_value.append(hashkey + ': FAILED')
        else:
            return_value.append(hashkey + ': OK')
            logger.info('\x1b[6;30;42m' + hashkey + ': OK\x1b[0m')
    return return_value


def retrieve_hashkeys_from_file(input_file, hashkeys):
    with open(input_file, 'r') as input_file:
        for line in input_file:
            if line:
                hashkeys.add(line.strip())


if __name__ == '__main__':
    sys.exit(main())
