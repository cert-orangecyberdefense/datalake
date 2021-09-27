import json
import sys

from datalake.common.config import Config
from datalake.common.logger import logger, configure_logging
from datalake.common.token_manager import TokenManager
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.engines.post_engine import AdvancedSearch


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
    configure_logging(args.loglevel)

    # Load api_endpoints and tokens
    endpoint_config = Config().load_config()
    token_manager = TokenManager(endpoint_config, environment=args.env)
    with open(args.query_body_path, 'r') as query_body_file:
        query_body = json.load(query_body_file)
    logger.debug(f'Retrieving query hash for query body: {query_body}')

    advanced_search = AdvancedSearch(endpoint_config, args.env, token_manager)

    response = advanced_search.get_threats(query_body, limit=0)
    if not response or 'query_hash' not in response:
        logger.error("Couldn't retrieve a query hash, is the query body valid ?")
        exit(1)
    query_hash = response['query_hash']
    if args.output:
        with open(args.output, 'w') as output:
            output.write(query_hash)
        logger.info(f'Query hash saved in {args.output}')
    else:
        logger.info(f'Query hash associated: {query_hash}')


if __name__ == '__main__':
    sys.exit(main())
