import json
import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.get_engine import BulkSearch


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()
    logger.debug(f'START: get_threats_from_query_hash.py')

    # Load initial args
    parser = starter.start('Retrieve a list of response from a given query hash.')
    parser.add_argument(
        '--query_fields',
        help='fields to be retrieved from the threat (default: only the hashkey)',
        nargs='+',
        default=['threat_hashkey'],
    )
    parser.add_argument(
        '--list',
        help='Turn the output in a list (require query_fields to be a single element)',
        action='store_true',
    )
    required_named = parser.add_argument_group('required arguments')
    required_named.add_argument(
        'query_hash',
        help='the query hash from which to retrieve the response hashkeys',
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    if len(args.query_fields) > 1 and args.list:
        parser.error("List output format is only available if a single element is queried (via query_fields)")

    # Load api_endpoints and tokens
    endpoint_url, main_url, tokens = starter.load_config(args)
    logger.debug(f'Start to search for threat from the query hash:{args.query_hash}')

    url_event = main_url + endpoint_url['endpoints']['bulk-search']
    bulk_search = BulkSearch(url_event, main_url, tokens)

    response = bulk_search.get_threats(args.query_hash, args.query_fields)
    original_count = response.get('count', 0)
    logger.info(f'Number of threat that have been retrieved: {original_count}')

    formatted_output = format_output(response, args.list)
    if args.output:
        with open(args.output, 'w') as output:
            output.write(formatted_output)
    else:
        logger.info(formatted_output)

    if args.output:
        logger.info(f'Threats saved in {args.output}')
    else:
        logger.info('Done')


def format_output(response: dict, one_threat_per_line=False) -> str:
    if one_threat_per_line:
        threat_list = []
        for result in response.get('results', []):
            if result:
                threat_list += result
        return '\n'.join(threat_list)
    else:
        return json.dumps(response, sort_keys=True, indent=4)


if __name__ == '__main__':
    sys.exit(main())
