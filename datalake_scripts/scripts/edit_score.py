import sys, json
from collections import OrderedDict
from datalake import ThreatType
from datalake import Datalake
from datalake.common.logger import logger
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import save_output


def main(override_args=None):
    """Method to start the script"""
    # Load initial args
    parser = BaseScripts.start('Edit scores of a specified list of ids (hashkeys)')
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
        '-w',
        '--whitelist',
        help='Whitelist the input, equivalent to setting all threat types at 0.',
        action='store_true',
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

    if args.whitelist:
        parsed_threat_type = get_whitelist_threat_types()
    else:
        if not args.threat_types or len(args.threat_types) % 2 != 0:
            parser.error("threat_types invalid ! should be like: ddos 50 scam 15")
        parsed_threat_type = parse_threat_types(args.threat_types)
    # removing duplicates while preserving order
    hashkeys = args.hashkeys
    if args.input_file:
        retrieve_hashkeys_from_file(args.input_file, hashkeys)
    hashkeys_chunks = chunk_list(list(OrderedDict.fromkeys(hashkeys)) if hashkeys else [])
    
    dtl = Datalake(env=args.env, log_level=args.loglevel)
    response_list = []
    for index, hashkeys in enumerate(hashkeys_chunks):
        try:
            response = dtl.Threats.edit_score_by_hashkeys(hashkeys, parsed_threat_type, args.permanent,)
        except ValueError as e:
            logger.warning('\x1b[6;30;41mBATCH ' + str(index+1) + ': FAILED\x1b[0m')
            for hashkey in hashkeys:
                response_list.append(hashkey + ': FAILED')
                logger.warning('\x1b[6;30;41m' + hashkey + ': FAILED\x1b[0m')
            logger.warning(e)
        else:
            logger.info('\x1b[6;30;42mBATCH ' + str(index+1) + ': OK\x1b[0m')
            for hashkey in hashkeys:
                response_list.append(hashkey + ': OK')

    if args.output:
        save_output(args.output, response_list)
        logger.info(f'Results saved in {args.output}\n')
    logger.debug(f'END: edit_score.py')


def chunk_list(lst):
    output = []
    for i in range(0, len(lst), 100):
        output.append(lst[i:i+100])
    return output


def parse_threat_types(threat_types: list) -> list:
    threat_type_parsed = {}
    for i in range(0, len(threat_types), 2):
        score = int(threat_types[i + 1])
        try:
            threat_type = ThreatType(threat_types[i])
        except ValueError:
            raise ValueError(f'Unknow threat_types: {threat_types[i]} {score},'
                             f' please use only value in {[e.value for e in ThreatType]}.')
        if score < 0 or score > 100:
            raise ValueError(f'Wrong score: {threat_type} {score}, '
                             'please use only value in [0, 100].')
        threat_type_parsed[threat_type] = int(score)
    threat_type_formatted = []
    for key, value in threat_type_parsed.items():
        threat_type_formatted.append({'threat_type': key, 'score': value})
    return threat_type_formatted


def get_whitelist_threat_types():
    return [{'threat_type': threat_type, 'score': 0} for threat_type in ThreatType]


def retrieve_hashkeys_from_file(input_file, hashkeys):
    with open(input_file, 'r', encoding='utf-8') as input_file:
        for line in input_file:
            line = line.strip()
            if line:
                hashkeys.append(line)


if __name__ == '__main__':
    sys.exit(main())
