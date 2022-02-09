import json
import sys

from datalake import Datalake
from datalake.common.ouput import Output
from datalake.common.logger import logger, configure_logging
from datalake_scripts.common.base_script import BaseScripts


def main(override_args=None):
    logger.debug(f'START: get_query_hash.py')

    # Load initial args
    parser = BaseScripts.start('Retrieve a query hash from a query body (a json used for the Advanced Search).')
    required_named = parser.add_argument_group('required arguments')
    required_named.add_argument(
        'query_body_path',
        help='path to the json file containing the query body',
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    # Load api_endpoints and tokens
    with open(args.query_body_path, 'r') as query_body_file:
        query_body = json.load(query_body_file)
    logger.debug(f'Retrieving query hash for query body: {query_body}')

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    resp = dtl.AdvancedSearch.advanced_search_from_query_body(query_body, limit=0, offset=0,
                                                              output=Output.JSON)
    if not resp or 'query_hash' not in resp:
        logger.error("Couldn't retrieve a query hash, is the query body valid ?")
        exit(1)
    query_hash = resp['query_hash']
    if args.output:
        with open(args.output, 'w') as output:
            output.write(query_hash)
        logger.info(f'Query hash saved in {args.output}')
    else:
        logger.info(f'Query hash associated: {query_hash}')


if __name__ == '__main__':
    sys.exit(main())
