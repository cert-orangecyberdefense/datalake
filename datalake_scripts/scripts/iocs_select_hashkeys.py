import argparse
import datetime
import logging
import re
import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.engines.post_engine import AdvancedSearch
from datalake_scripts.common.logger import logger


SUPPORTED_THREATS_TYPES = ['malware', 'phishing', 'ddos']
SUPPORTED_ATOM_TYPES = ['url', 'domain', 'ip']

DATE_REGEX_VALIDATION = r'^\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])$'
DATE_FORMAT = '%Y-%m-%d'


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()
    parser = _set_up_args()

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    is_valid, validation_msg = _validate_args(args)
    if not is_valid:
        parser.error(validation_msg)

    # always loglevel will be INFO
    args.loglevel = logging.INFO

    # load api_endpoints and tokens
    endpoint_config, main_url, tokens = starter.load_config(args)
    advanced_search = AdvancedSearch(endpoint_config, args.env, tokens)
    response = advanced_search.get_threats(_build_query_body(args), limit=args.max_samples)

    if 'results' in response:
        hashkeys = []
        for result in response['results']:
            hashkeys.append(result['hashkey'])
    else:
        logger.warning('API response hasnt results')

    if hashkeys:
        filename = _get_output_file_name(args)
        starter.save_output(filename, hashkeys)
        logger.info(f'results saved in {filename}')
    else:
        logger.warning('no hashkey was retrieved. Output file wont be created')

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
        choices=SUPPORTED_THREATS_TYPES
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

    # validate if dates are well formatted
    from_date = re.match(DATE_REGEX_VALIDATION, args.from_date)
    to_date = re.match(DATE_REGEX_VALIDATION, args.to_date)

    if not from_date or not to_date:
        return False, f'--from-date and --to-date should exists and be formatted as YYYY-mm-dd'

    # validate if date range is coherent
    try:
        from_date = datetime.datetime.strptime(from_date.string, DATE_FORMAT)
        to_date = datetime.datetime.strptime(to_date.string, DATE_FORMAT)

        if to_date < from_date:
            return False, f'--to-date {args.to_date} should be higher than --from-date {args.from_date}'

    except ValueError as e:
        return (
            False,
            f"""
            --from-date or --to-date are well formatted but an exception was raised while type conversion
            Exception: {e}
            """
        )

    if args.max_score < args.min_score:
        return False, f'--max-score {args.max_score} should be higher than --min-score {args.min_score}'

    return is_valid, validation_msg


def _build_query_body(args):
    """ this method builds dynamically the query body """
    return {
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


def _get_output_file_name(args):
    score_range = f'[{args.min_score}-{args.max_score}]'
    return f'hashkeys-{args.from_date}-{args.to_date}-{args.threat_type}-{args.atom_type}-{score_range}.txt'


if __name__ == '__main__':
    sys.exit(main())
