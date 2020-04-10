import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.post_engine import AddThreatsPost


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()

    # Load initial args
    parser = starter.start('Submit a new threat to Datalake from a file')
    required_named = parser.add_argument_group('required arguments')
    csv_controle = parser.add_argument_group('CSV control arguments')
    required_named.add_argument(
        '-i',
        '--input',
        help='read threats to add from FILE',
        required=True,
    )
    required_named.add_argument(
        '-a',
        '--atom_type',
        help='set it to define the atom type',
        required=True,
    )
    csv_controle.add_argument(
        '--is_csv',
        help='set if the file input is a CSV',
        action='store_true',
    )
    csv_controle.add_argument(
        '-d',
        '--delimiter',
        help='set the delimiter of the CSV file',
        default=',',
    )
    csv_controle.add_argument(
        '-c',
        '--column',
        help='select column of the CSV file, starting at 1',
        type=int,
        default=1,
    )
    parser.add_argument(
        '-p',
        '--public',
        help='set the visibility to public',
        action='store_true',
    )
    parser.add_argument(
        '-w',
        '--whitelist',
        help='set it to define the added threats as whitelist',
        action='store_true',
    )
    parser.add_argument(
        '-t',
        '--threat_types',
        nargs='+',
        help='choose specific threat types and their score, like: ddos 50 scam 15',
        default=[],
    )
    parser.add_argument(
        '--tag',
        nargs='+',
        help='add a list of tags',
        default=[],
    )
    parser.add_argument(
        '--link',
        help='add link as external_analysis_link',
        nargs='+',
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()
    logger.debug(f'START: add_new_threats.py')

    if not args.threat_types and not args.whitelist:
        parser.error("threat types is required if the atom is not for whitelisting")

    # Load api_endpoints and tokens
    endpoint_url, main_url, tokens = starter.load_config(args)
    url_manual_threats = main_url + endpoint_url['endpoints']['threats-manual']
    post_engine_add_threats = AddThreatsPost(url_manual_threats, main_url, tokens)
    if args.is_csv:
        list_new_threats = starter._load_csv(args.input, args.delimiter, args.column - 1)
    else:
        list_new_threats = starter._load_list(args.input)
    threat_types = AddThreatsPost.parse_threat_types(args.threat_types) or []
    response_dict = post_engine_add_threats.add_threats(
        list_new_threats,
        args.atom_type,
        args.whitelist,
        threat_types,
        args.public,
        args.tag,
        args.link,
    )

    if args.output:
        starter.save_output(args.output, response_dict)
        logger.debug(f'Results saved in {args.output}\n')
    logger.debug(f'END: add_new_threats.py')


if __name__ == '__main__':
    sys.exit(main())
