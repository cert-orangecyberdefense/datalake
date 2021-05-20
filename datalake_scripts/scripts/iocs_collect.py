import argparse
import logging
import sys

from datalake_scripts.common.logger import configure_logging
from datalake_scripts.scripts import iocs_select_hashkeys, iocs_select_uids
from datalake_scripts.scripts.iocs_select_hashkeys import make_output_file_name


def main(override_args=None):
    """Method to start the script"""
    configure_logging(logging.DEBUG)
    parser = _set_up_args()

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    for args.threat_type in args.threat_types:
        for args.atom_type in args.atom_types:
            for args.min_score, args.max_score in args.score_ranges:
                hashkeys_cmd = [
                    '--from-date', args.from_date,
                    '--to-date', args.to_date,
                    '--threat-type', args.threat_type,
                    '--atom-type', args.atom_type,
                    '--min-score', str(args.min_score),
                    '--max-score', str(args.max_score),
                    '--max-samples', str(args.max_samples)
                ]
                iocs_select_hashkeys.main(hashkeys_cmd)

                hashkey_output_filename = make_output_file_name(args)
                uids_cmd = [
                    '--file', hashkey_output_filename,
                    '--max-duration', str(args.max_duration)
                ]
                iocs_select_uids.main(uids_cmd)


def _set_up_args():
    """ this method set flags and args up for `iocs_select_hashkeys` command """
    parser = argparse.ArgumentParser(description='execute `iocs_select_hashkeys` and `iocs_select_uids` with all '
                                                 'possible permutations taken from arguments')

    parser.add_argument('-t1', '--from-date', required=True, help='date from which hashkeys are selected YYYY-mm-dd')
    parser.add_argument('-t2', '--to-date', required=True, help='date until hashkeys are selected YYYY-mm-dd')
    parser.add_argument('-N', '--max-samples', required=True, type=int, help='max number of hashkeys to select')
    parser.add_argument('-M', '--max-duration', required=True, type=int, help='max duration in days')

    parser.add_argument(
        '-e',
        '--env',
        help='execute on specified environment [Default: prod]',
        choices=['prod', 'dtl2', 'preprod'],
        default='prod',
    )
    parser.add_argument(
        '-T',
        '--threat-types',
        nargs='+',
        required=True,
        help='threat types to select',
        choices=iocs_select_hashkeys.SUPPORTED_THREAT_TYPES
    )
    parser.add_argument(
        '-A',
        '--atom-types',
        nargs='+',
        required=True,
        help='threat type to select',
        choices=iocs_select_hashkeys.SUPPORTED_ATOM_TYPES
    )
    parser.add_argument(
        '-S',
        '--score-ranges',
        nargs='+',
        required=True,
        type=score_range_type,
        help='score ranges min-1,max-1 min-2,max-2 min-3,max-3 ...'
    )
    return parser


def score_range_type(value):
    min_score, max_score = map(int, value.split(','))
    return min_score, max_score


if __name__ == '__main__':
    sys.exit(main())
