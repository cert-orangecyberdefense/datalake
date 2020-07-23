import sys

from collections import OrderedDict
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.get_engine import LookupThreats


def main(override_args=None):
    """Method to start the script"""
    starter = BaseScripts()

    # Load initial args
    parser = starter.start('Submit a new threat to Datalake from a file')
    required_named = parser.add_argument_group('required arguments')
    csv_controle = parser.add_argument_group('CSV control arguments')

    parser.add_argument(
        'threats',
        help='threats to lookup',
        nargs='*',
    )
    parser.add_argument(
        '-i',
        '--input',
        help='read threats to add from FILE',
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
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()
    logger.debug(f'START: lookup_threats.py')

    if not args.threats and not args.input:
        parser.error("either a threat or an input_file is required")

    # Load api_endpoints and tokens
    endpoint_url, main_url, tokens = starter.load_config(args)
    url_lookup_threats = main_url + endpoint_url['endpoints']['lookup']
    get_engine_lookup_threats = LookupThreats(url_lookup_threats, main_url, tokens)
    list_threats = list(args.threats) if args.threats else []
    if args.input:
        if args.is_csv:
            try:
                list_threats = list_threats + starter._load_csv(args.input, args.delimiter, args.column - 1)
            except ValueError as ve:
                logger.error(ve)
                exit()
        else:
            list_threats = list_threats + starter._load_list(args.input)
    list_threats = list(OrderedDict.fromkeys(list_threats))  # removing duplicates while preserving order
    response_dict = get_engine_lookup_threats.lookup_threats(
        list_threats,
        args.atom_type,
    )

    if args.output:
        starter.save_output(args.output, response_dict)
        logger.debug(f'Results saved in {args.output}\n')
    logger.debug(f'END: lookup_threats.py')


if __name__ == '__main__':
    sys.exit(main())
