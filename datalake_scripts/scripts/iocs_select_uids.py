import argparse
import datetime
import logging
import os
import re
import sys

from datetime import timedelta
from os import listdir
from os.path import isfile, join
from tqdm import tqdm

from datalake_scripts import Events
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger

SUPPORTED_THREAT_TYPES = ['malware', 'phishing', 'ddos']
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
        file_parts = file.split('_')
        max_score = file_parts[-1][:-4]
        min_score = file_parts[-2]
        atom_type = file_parts[-3]
        threat_type = file_parts[-4]

        # get dates from input filename
        args.created_until = datetime.datetime.strptime(file_parts[-5], DATE_FORMAT)
        args.created_since = args.created_until - timedelta(days=args.max_duration)

        # request event history for each hashkey
        ioc_uids = []
        with tqdm(total=len(args.hashkeys)) as progress_bar:
            for hashkey in args.hashkeys:
                progress_bar.set_description(f'getting uids from hashkey `{hashkey}` from input file `{file}`')
                response = events.get_events(
                    hashkey,
                    limit=EVENTS_LIMIT,
                    offset=0,
                    ordering=['timestamp_created'],
                    created_since=args.created_since,
                    created_until=args.created_until
                )

                if 'results' in response:
                    for result in response['results']:
                        ioc_uids.append(result['ioc_uid'])
                else:
                    logger.warning('API response has not results')

                progress_bar.update(1)

        if ioc_uids:
            filename = _make_output_file_name(args, threat_type, atom_type, min_score, max_score)
            starter.save_output(filename, ioc_uids)
            logger.info(f'results saved in {filename}')
        else:
            logger.warning('no uids were retrieved. Output file wont be created')


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
        help='path to hashkey file. Filename must match with `hashkeys-t1-t2-T-A-I.txt` format'
    )
    parser.add_argument(
        '-d',
        '--directory',
        help='path to dir containing hashkey files. All files matching `hashkeys-t1-t2-T-A-I.txt` format will be loaded'
    )
    parser.add_argument(
        '-M',
        '--max-duration',
        required=True,
        type=int,
        help='maximum duration in days'
    )

    return parser


def _validate_args(args):
    """
    this method takes given args and validate them
    :param args: Namespace
    :return: (bool, str)
    """
    global INPUT_FILES
    is_valid, validation_msg = True, 'ok'

    if not args.file and not args.directory:
        return False, f'you must define at least one of --file or --directory'

    # validate input filename format and existence
    if args.file:
        is_valid, validation_msg = _validate_input_filename(args.file)
        if not is_valid:
            return is_valid, validation_msg
        INPUT_FILES += [args.file]

    # validate if input directory exists
    if args.directory:
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

    'hashkeys_2021-01-31_2021-04-13_malware_ip_10_80.txt'                             relative
    '/some/path/to_file/hashkeys_2021-01-31_2021-04-13_malware_ip_10_80.txt'          absolut
    """
    is_valid, validation_msg = True, 'ok'
    input_filename_regex_validation = r'hashkeys_' \
                                      r'(\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])_?){2}_' \
                                      r'(\w+-?){2}_' \
                                      r'((\d{1,2}|100)_?){2}\.txt$'

    regex_results = re.search(input_filename_regex_validation, filename)
    if not regex_results:
        return False, f'{filename} should be formatted as following `hashkeys_t1_t2_T_A_I.txt`'
    elif not os.path.exists(filename):
        return False, f'{filename} doesnt exist'
    return is_valid, validation_msg


def _make_output_file_name(args, threat_type, atom_type, min_score, max_score):
    date_range = f'{args.created_since.strftime(DATE_FORMAT)}_{args.created_until.strftime(DATE_FORMAT)}'
    score_range = f'{min_score}_{max_score}'
    return f'iocs_{date_range}_{threat_type}_{atom_type}_{score_range}.txt'


if __name__ == '__main__':
    sys.exit(main())
