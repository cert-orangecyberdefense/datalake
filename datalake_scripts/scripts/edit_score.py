import sys
from collections import OrderedDict

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.post_engine import ThreatsScoringPost, AddThreatsPost


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()

    # Load initial args
    parser = starter.start('Edit scores of a specified list of ids (hashkeys)')
    parser.add_argument(
        'hashkeys',
        help='hashkeys of the threat to edit score.',
        nargs='*',
    )
    parser.add_argument(
        '-i',
        '--input_file',
        help='hashkey txt file, with one hashkey by line.',
    )
    parser.add_argument(
        '-t',
        '--threat_types',
        nargs='+',
        help='Choose specific threat types and their score, like: ddos 50 scam 15.',
    )
    parser.add_argument(
        '--permanent',
        help='''Permanent: all values will override any values provided by both newer and
            older IOCs. Newer IOCs with override_type permanent can still override old permanent changes.
            temporary: all values should override any values provided by older IOCs,
            but not newer ones.''',
        action='store_true',
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    logger.debug(f'START: edit_score.py')

    if not args.hashkeys and not args.input_file:
        parser.error("either a hashkey or an input_file is required")

    if not args.threat_types or len(args.threat_types) % 2 != 0:
        parser.error("threat_types invalid ! should be like: ddos 50 scam 15")
    parsed_threat_type = AddThreatsPost.parse_threat_types(args.threat_types)
    # removing duplicates while preserving order
    hashkeys = args.hashkeys
    if args.input_file:
        retrieve_hashkeys_from_file(args.input_file, hashkeys)
    hashkeys = list(OrderedDict.fromkeys(hashkeys)) if hashkeys else []
    # Load api_endpoints and tokens
    endpoint_url, main_url, tokens = starter.load_config(args)
    url_threats = main_url + endpoint_url['endpoints']['threats']
    post_engine_edit_score = ThreatsScoringPost(url_threats, main_url, tokens)

    response_dict = post_engine_edit_score.post_new_score_from_list(
        hashkeys,
        parsed_threat_type,
        'permanent' if args.permanent else 'temporary',
    )

    if args.output:
        starter.save_output(args.output, response_dict)
        logger.info(f'Results saved in {args.output}\n')
    logger.debug(f'END: edit_score.py')


def retrieve_hashkeys_from_file(input_file, hashkeys):
    with open(input_file, 'r', encoding='utf-8') as input_file:
        for line in input_file:
            line = line.strip()
            if line:
                hashkeys.append(line)


if __name__ == '__main__':
    sys.exit(main())
