import argparse
import datetime
import logging
import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.engines.post_engine import AdvancedSearch
from datalake_scripts.common.logger import logger

SUPPORTED_THREAT_TYPES = ['malware', 'phishing', 'ddos']
SUPPORTED_ATOM_TYPES = ['url', 'domain', 'ip']

DATE_FORMAT = '%Y-%m-%d'


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()
    parser = _set_up_args()

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    args.loglevel = logging.INFO
    is_valid, validation_msg = _validate_args(args)
    if not is_valid:
        parser.error(validation_msg)

    # load api_endpoints and tokens
    endpoint_config, main_url, tokens = starter.load_config(args)
    advanced_search = AdvancedSearch(endpoint_config, args.env, tokens)
    response = advanced_search.get_threats(_build_query_body(args), limit=args.max_samples)

    if not response or 'results' not in response:
        logger.error('API response has not results')
        exit(1)

    hashkeys = [result['hashkey'] for result in response['results']]

    if hashkeys:
        filename = _make_output_file_name(args)
        starter.save_output(filename, hashkeys)
        logger.info(f'results saved in {filename}')
    else:
        logger.warning('no hashkey were retrieved. Output file wont be created')

    # TODO
    # log if --max-samples was not satisfied
    # for example, if --max-samples is 200 but only 10 iocs hashkeys were collected


def _set_up_args():
    """ this method set flags and args up for `iocs_select_hashkeys` command """
    parser = argparse.ArgumentParser(description='retrieve hashkeys from data lake and store them in a file')
    parser.add_argument('-t1', '--from-date', required=True, help='date from which hashkeys are selected YYYY-mm-dd')
    parser.add_argument('-t2', '--to-date', required=True, help='date until hashkeys are selected YYYY-mm-dd')
    parser.add_argument('-N', '--max-samples', type=int, default=500, help='maximum number of hashkeys to be selected')

    parser.add_argument(
        '-e',
        '--env',
        help='execute on specified environment [Default: prod]',
        choices=['prod', 'dtl2', 'preprod'],
        default='prod',
    )
    parser.add_argument(
        '-T',
        '--threat-type',
        required=True,
        help='threat type to select',
        choices=SUPPORTED_THREAT_TYPES
    )
    parser.add_argument(
        '-A',
        '--atom-type',
        required=True,
        help='threat type to select',
        choices=SUPPORTED_ATOM_TYPES
    )
    parser.add_argument(
        '-I',
        '--max-score',
        required=True,
        type=int,
        choices=range(0, 101),
        metavar='[0-100]',
        help='upper score limit to select hashkeys'
    )
    parser.add_argument(
        '-i',
        '--min-score',
        required=True,
        type=int,
        choices=range(0, 101),
        metavar='[0-100]',
        help='lower score limit to select hashkeys'
    )
    return parser


def _validate_args(args):
    """
    this method takes given args and validate them
    :param args: Namespace
    :return: (bool, str)
    """
    is_valid = True
    validation_msg = 'ok'

    # validate if date range is coherent
    try:
        from_date = datetime.datetime.strptime(args.from_date, DATE_FORMAT)
        to_date = datetime.datetime.strptime(args.to_date, DATE_FORMAT)

        if to_date < from_date:
            return False, f'--to-date {args.to_date} should be higher than --from-date {args.from_date}'

    except ValueError as e:
        return False, f'--from-date or --to-date are not valid dates or are not formatted as YYYY-mm-dd Exception: {e}'

    if args.max_score < args.min_score:
        return False, f'--max-score {args.max_score} should be higher than --min-score {args.min_score}'

    return is_valid, validation_msg


def _build_query_body(args):
    """ this method builds dynamically the query body """
    return {
        'AND': [
            {
                'AND': [
                    {
                        'field': 'atom_type',
                        'value': args.atom_type,
                        'type': 'filter'
                    },
                    {
                        'field': 'threat_types',
                        'value': args.threat_type,
                        'type': 'filter'
                    },
                    {
                        "field": "risk",
                        "inner_params": {
                            "threat_types": [args.threat_type]
                        },
                        "range": {
                            "gt": args.min_score,
                            "lt": args.max_score
                        },
                        "type": "filter"
                    },
                    {
                        "field": "last_updated",
                        "range": {
                            "gte": args.from_date,
                            "lte": args.to_date
                        },
                        "type": "filter"
                    }
                ]
            }
        ]
    }


def _make_output_file_name(args):
    date_range = f'{args.from_date}_{args.to_date}'
    score_range = f'{args.min_score}_{args.max_score}'

    return f'hashkeys_{date_range}_{args.threat_type}_{args.atom_type}_{score_range}.txt'


if __name__ == '__main__':
    sys.exit(main())
