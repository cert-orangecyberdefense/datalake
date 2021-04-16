import argparse
import datetime
import logging
import os
import re
import sys
from datetime import timedelta
from os import listdir
from os.path import isfile, join

from datalake_scripts import Events
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger

SUPPORTED_THREATS_TYPES = ['malware', 'phishing', 'ddos']
SUPPORTED_ATOM_TYPES = ['url', 'domain', 'ip']

DATE_FORMAT = '%Y-%m-%d'
INPUT_FILES = []
EVENTS_LIMIT = 5000


def main(override_args=None):
    """Method to start the script"""
    global INPUT_FILES

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

    # load api_endpoints, tokens and events engine
    endpoint_config, main_url, tokens = starter.load_config(args)
    events = Events(endpoint_config, args.env, tokens)

    # remove duplicated input files
    # it could happens when a directory contains a file and the same file is passed with --file arg
    INPUT_FILES = list(set(INPUT_FILES))

    for file in INPUT_FILES:
        logger.info(f'{file} will be used as hashkeys input')
        args.hashkeys = starter._load_list(file)

        # get data from input filename
        file_parts = file.split('-')
        max_score = file_parts[-1][:-4]
        min_score = file_parts[-2]
        atom_type = file_parts[-3]
        threat_type = file_parts[-4]

        # get dates from input filename
        args.created_until = datetime.datetime.strptime('-'.join(file_parts[-7:-4]), DATE_FORMAT)
        args.created_since = args.created_until - timedelta(days=args.max_duration)

        response = events.get_events(_build_request_payload(args))
        ioc_uids = []
        if 'results' in response:
            for result in response['results']:
                ioc_uids.append(result['ioc_uid'])
        else:
            logger.warning('API response hasnt results')

        if ioc_uids:
            filename = _get_output_file_name(args, threat_type, atom_type, min_score, max_score)
            starter.save_output(filename, ioc_uids)
            logger.info(f'results saved in {filename}')
        else:
            logger.warning('no uids were retrieved. Output file wont be created')



    # TODO
    # log if --max-samples was not satisfied
    # for example, if --max-samples is 200 but only 10 iocs hashkeys were collected


def _set_up_args():
    """ this method set flags and args up for `iocs_select_uids` command """
    parser = argparse.ArgumentParser(description='retrieve uids from hashkey files and store them in a file')

    parser.add_argument(
        '-e',
        '--env',
        help='execute on specified environment [Default: prod]',
        choices=['prod', 'dtl2', 'preprod'],
        default='prod',
    )
    parser.add_argument(
        '-f',
        '--file',
        required=True,
        help='path to hashkey file. Filename must match with `hashkeys-t1-t2-T-A-I.txt` format'
    )
    parser.add_argument(
        '-d',
        '--directory',
        required=True,
        help='path to dir containing hashkey files. All files matching `hashkeys-t1-t2-T-A-I.txt` format will be loaded'
    )
    parser.add_argument(
        '-M',
        '--max-duration',
        required=True,
        type=int,
        help='maximum duration in days'
    )

    # parser.add_argument('-t1', '--from-date', required=True, help='date from which hashkeys are selected YYYY-mm-dd')
    # parser.add_argument('-t2', '--to-date', required=True, help='date until hashkeys are selected YYYY-mm-dd')
    # parser.add_argument('-N', '--max-samples', type=int, default=500, help='maximum number of hashkeys to be selected')
    # parser.add_argument(
    #     '-T',
    #     '--threat-type',
    #     required=True,
    #     help='threat type to select',
    #     choices=SUPPORTED_THREATS_TYPES
    # )
    # parser.add_argument(
    #     '-A',
    #     '--atom-type',
    #     required=True,
    #     help='threat type to select',
    #     choices=SUPPORTED_ATOM_TYPES
    # )
    # parser.add_argument(
    #     '-I',
    #     '--max-score',
    #     required=True,
    #     type=int,
    #     choices=range(0, 101),
    #     metavar='[0-100]',
    #     help='upper score limit to select hashkeys'
    # )
    # parser.add_argument(
    #     '-i',
    #     '--min-score',
    #     required=True,
    #     type=int,
    #     choices=range(0, 101),
    #     metavar='[0-100]',
    #     help='lower score limit to select hashkeys'
    # )
    return parser


def _validate_args(args):
    """
    this method takes given args and validate them
    :param args: Namespace
    :return: (bool, str)
    """
    global INPUT_FILES

    # validate input filename format and existence
    is_valid, validation_msg = _validate_input_filename(args.file)
    if not is_valid:
        return is_valid, validation_msg

    INPUT_FILES += [args.file]

    # validate if input directory exists
    if not os.path.isdir(args.directory):
        return False, f'--directory {args.directory} doesnt exists'

    # validate if input directory has files with correct name format
    for f in listdir(args.directory):
        file_path = join(args.directory, f)
        if isfile(file_path) and _validate_input_filename(file_path)[0]:
            INPUT_FILES += [file_path]

    if not INPUT_FILES:
        return False, f'--directory {args.directory} doesnt contain valid input files'

    if args.max_duration < 0:
        return False, f'--max-duration {args.max_duration} must be a positive int'

    return is_valid, validation_msg


def _validate_input_filename(filename):
    """
    this method takes a filename and validates that its name is well formatted and the file exists
    :param filename: str
    :return: (bool, str)

    'hashkeys-2021-01-31-2021-04-13-malware-ip-10-80.txt'                             relative
    '/some/path/to_file/hashkeys-2021-01-31-2021-04-13-malware-ip-10-80.txt'          absolut
    """
    is_valid, validation_msg = True, 'ok'
    input_filename_regex_validation = r'hashkeys-' \
                                      r'(\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])-?){2}-' \
                                      r'(\w+-?){2}-' \
                                      r'(\d{1,2}-?){2}\.txt$'

    regex_results = re.search(input_filename_regex_validation, filename)
    if not regex_results:
        return False, f'{filename} should be formatted as following `hashkeys-t1-t2-T-A-I.txt`'
    elif not os.path.exists(filename):
        return False, f'{filename} doesnt exist'
    return is_valid, validation_msg


def _build_request_payload(args):
    """ this method builds dynamically the request payload """
    return {
        'limit': EVENTS_LIMIT,
        "created_since": args.created_since,
        "created_until": args.created_until,
        'ordering': [
            'first_seen'
        ],
        'hashkeys': args.hashkeys
    }


def _get_output_file_name(args, threat_type, atom_type, min_score, max_score):
    date_range = f'{args.created_since.strftime(DATE_FORMAT)}-{args.created_until.strftime(DATE_FORMAT)}'
    score_range = f'{min_score}-{max_score}'
    return f'iocs-{date_range}-{threat_type}-{atom_type}-{score_range}.txt'


if __name__ == '__main__':
    sys.exit(main())
