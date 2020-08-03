import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.get_engine import AdvancedSearchGet
from datalake_scripts.engines.post_engine import AdvancedSearchPost

query_hashes = ['5adb93d0bf66fd1cde8b41f72592fa37', '09d21b81f96351a7f78a2cc526769b69',
                '23ed1c5570f9c84629cc63e7bcf17bf1', '13a81f8e9711b4204df307b0dab4078f',
                'fc0460f022428819c7b290baa7ee17b1', 'd05031cf8898a1973c8a3dc39f52d93c',
                '54f119e5c8866e42cefafd0435660fee', 'c99480094bb22668e94fa639a506c103',
                'd95a3923a8efeb7bd58dc0c3f25fed81', '7fae28bea93e17855b709bcd62daccf3',
                '5bb00e46f601985a2c63b547b19c4274', '627d8b824656ad6e2486927f25bd980a',
                '00cb96699a835241b1cb19eb7061aed5', 'a60a829ff5d1569437b27f2cdfefaad1',
                '824a0c3af7438d0e291a8ee0ef3cb5c8']


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()
    logger.debug(f'START: get_stats.py')
    # Load initial args
    parser = starter.start('Retrieve a list of response from a given query hash.')
    parser.add_argument(
        '-t',
        '--atom_types',
        help='atom_types aggregated in stats.',
        nargs='*',
    )
    parser.add_argument(
        '-s',
        '--scores',
        help='minimum scores in stats.',
        nargs='*',
    )
    parser.add_argument(
        '--count_events',
        help='''set it to add the events number for each source.''',
        action='store_true',
    )
    parser.add_argument(
        '--all_stats',
        help='''set it to make the stats on all 5 atoms types and score of 60,70,80''',
        action='store_true',
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    # Load api_endpoints and tokens
    endpoint_url, main_url, tokens = starter.load_config(args)

    url_event = main_url + endpoint_url['endpoints']['advanced-queries']
    count_per_source = {}
    if args.all_stats:
        advanced_search = AdvancedSearchGet(url_event, main_url, tokens)
        for query_hash in query_hashes:
            response = advanced_search.get_threats(query_hash)['results']
            count_per_source = compute_stats(response, count_per_source, args.count_events)
    else:
        advanced_search = AdvancedSearchPost(url_event, main_url, tokens)
        for atom_type in args.atom_types:
            for score in args.scores:
                response = advanced_search.get_threats(create_payload(atom_type, score))['results']
                count_per_source = compute_stats(response, count_per_source, args.count_events)
    logger.info('aggregated result: '+str(extract_top(count_per_source)))
    logger.debug(f'Results saved in {args.output}\n')
    logger.debug(f'END: add_new_threats.py')


def create_payload(atom_type: str, score: int) -> dict:
    return {
        "query_body": {
            "AND": [
                {
                    "field": "atom_type",
                    "multi_values": [
                        atom_type
                    ],
                    "type": "filter"
                },
                {
                    "field": "last_updated",
                    "type": "filter",
                    "value": 43200
                },
                {
                    "field": "risk",
                    "range": {
                        "gt": int(score)
                    },
                    "type": "filter"
                }
            ]
        }
    }


def compute_stats(response, count_per_source, count_events: bool):
    for result in response:
        sources = result['sources']
        for source in sources:
            count = source['count'] if count_events else 1
            count_per_source[source['source_id']] = count_per_source[source['source_id']] + count if \
                source['source_id'] in count_per_source.keys() else count
    return count_per_source


def extract_top(count_per_source, bar=10):
    top = [[0, ''] for i in range(bar)]
    for source in count_per_source.keys():
        for i in range(len(top)):
            if count_per_source[source] > top[i][0]:
                top[i] = [count_per_source[source], source]
                break
    return top


if __name__ == '__main__':
    sys.exit(main())
