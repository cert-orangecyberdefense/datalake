import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.get_engine import BulkSearch


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()
    logger.debug(f'START: get_threats_from_query_hash.py')

    # Load initial args
    parser = starter.start('Retrieve a list of hashkey from a given query hash.')
    required_named = parser.add_argument_group('required arguments')
    required_named.add_argument(
        '--query_hash',
        help='the query hash from which to retrieve the threats hashkeys',
        required=True,
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    # Load api_endpoints and tokens
    endpoint_url, main_url, tokens = starter.load_config(args)
    logger.debug(f'Start to search for threat hashkey from the query hash:{args.query_hash}')

    url_event = main_url + endpoint_url['endpoints']['bulk-search']
    search_engine_advance = BulkSearch(url_event, main_url, tokens)

    output = None
    if args.output:
        output = open(args.output, 'w+')
    for hashkey in search_engine_advance.get_threats_hashkeys(args.query_hash):
        if output:
            output.write(f'{hashkey}\n')
        else:
            logger.info(hashkey)
    if output:
        output.close()
    if args.output:
        logger.info(f'Threats hashkey list saved in {args.output}')
    else:
        logger.info('Done, no more threats hashkey to find')


if __name__ == '__main__':
    sys.exit(main())
