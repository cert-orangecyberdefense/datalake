import json
import sys
from parser import ParserError

from datalake_scripts import AtomValuesExtractor
from datalake_scripts.common.base_engine import BaseEngine
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.post_engine import BulkLookupThreats
from datalake_scripts.helper_scripts.utils import join_dicts


SUBCOMMAND_NAME = 'bulk_lookup_threats'
UNTYPED_ATOM_TYPE = 'untyped'
ATOM_TYPES_FLAGS = [
    'apk', 'asn', 'cc', 'crypto', 'cve', 'domain', 'email', 'file', 'fqdn',
    'iban', 'ip', 'ip_range', 'paste', 'phone_number', 'regkey', 'ssl', 'url'
]


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    starter = BaseScripts()
    parser = starter.start('Gets threats or hashkeys from given atom types and atom values.')
    supported_atom_types = parser.add_argument_group('Supported Atom Types')

    parser.add_argument(
        'untyped_atoms',
        help='untyped atom values to lookup. Useful when you do not know what is the atom type',
        nargs='*',
    )
    for atom_type in ATOM_TYPES_FLAGS:
        supported_atom_types.add_argument(
            f'--{atom_type}',
            action='append',
            help=f'set a single {atom_type} atom type with its value',
        )
    parser.add_argument(
        '-ad',
        '--atom-details',
        dest='hashkey_only',
        default=True,
        action='store_false',
        help='returns threats full details',
    )
    parser.add_argument(
        '-i',
        '--input',
        action='append',
        help='read threats to add from FILE. [atomtype:path/to/file.txt]',
    )
    parser.add_argument(
        '-ot',
        '--output-type',
        help='set to the output type desired {json,csv}. Default is json',
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()
    logger.debug(f'START: bulk_lookup_threats.py')

    # create output type header
    accept_header = {'Accept': None}

    if args.output_type:
        try:
            accept_header['Accept'] = BaseEngine.output_type2header(args.output_type)
        except ParserError as e:
            logger.exception(f'Exception raised while getting output type headers # {str(e)}', exc_info=False)
            exit(1)

    # to gather all typed atoms passed by arguments and input files
    typed_atoms = {}

    # set validations flags regarding the presence or absence of cli arguments
    has_file = False if args.input is None else True
    has_flag = False
    for flag in ATOM_TYPES_FLAGS:
        atom_values = getattr(args, flag)
        if atom_values is not None:
            typed_atoms[flag] = atom_values
            has_flag = True

    # validate that at least there is one untyped atom or one atom or one input file
    if (not has_flag and not has_file and not args.untyped_atoms) or (SUBCOMMAND_NAME in args.untyped_atoms):
        parser.error("you must provide at least one of following: untyped atom, atom type, input file.")

    # process input files
    if has_file:
        for input_file in args.input:
            file_atom_type, filename = get_atom_type_from_filename(input_file)
            logger.debug(f'file {filename} was recognized as {file_atom_type}')

            if file_atom_type == UNTYPED_ATOM_TYPE:
                args.untyped_atoms += starter._load_list(filename)
            else:
                typed_atoms.setdefault(file_atom_type, []).extend(starter._load_list(filename))

    # load api_endpoints and tokens
    endpoints_config, main_url, tokens = starter.load_config(args)
    post_engine_bulk_lookup_threats = BulkLookupThreats(endpoints_config, args.env, tokens)
    post_engine_atom_values_extractor = AtomValuesExtractor(endpoints_config, args.env, tokens)

    # lookup for atom types
    if args.untyped_atoms:
        atoms_values_extractor_response = post_engine_atom_values_extractor.atom_values_extract(args.untyped_atoms)
        if atoms_values_extractor_response['found'] > 0:
            typed_atoms = join_dicts(typed_atoms, atoms_values_extractor_response['results'])
        else:
            logger.warning('none of your untyped atoms could be typed')

        # find out what atoms couldn't be typed for printing them
        if atoms_values_extractor_response['not_found'] > 0:
            for atom_type, atom_list in atoms_values_extractor_response['results'].items():
                args.untyped_atoms = [
                    untyped_atom for untyped_atom in args.untyped_atoms
                    if untyped_atom not in atoms_values_extractor_response['results'][atom_type]
                ]

            logger.warning(f'\x1b[6;37;43m{"#" * 60} UNTYPED ATOMS {"#" * 47}\x1b[0m')
            logger.warning('\n'.join(args.untyped_atoms))
            logger.warning('')

    response = post_engine_bulk_lookup_threats.bulk_lookup_threats(
        threats=typed_atoms,
        additional_headers=accept_header,
        hashkey_only=args.hashkey_only
    )

    pretty_print(response, args.output_type)

    if args.output:
        starter.save_output(args.output, response)
        logger.debug(f'Results saved in {args.output}\n')

    logger.debug(f'END: lookup_threats.py')


def get_atom_type_from_filename(filename, input_delimiter=':'):
    """
    parse filename for getting the atom type that it contains and the cleaned filename as a list as following
    ['type', cleaned_file]
    """
    parts = filename.split(input_delimiter, 1)

    # typed files
    if len(parts) == 2 and parts[0] in ATOM_TYPES_FLAGS:
        return parts

    # untyped files
    if len(parts) == 1:
        return [UNTYPED_ATOM_TYPE, parts[0]]

    logger.error(f'{filename} filename could not be treated `atomtype:path/to/file.txt`')
    exit(1)


def pretty_print(raw_response, stdout_format):
    """
     takes the API raw response and format it for be printed as stdout
     stdout_format possible values {json, csv}
    """
    if stdout_format == 'json':
        logger.info(json.dumps(raw_response, indent=4, sort_keys=True))
        return

    if stdout_format == 'csv':
        logger.info(raw_response)
        return

    blue_bg = '\033[104m'
    eol = '\x1b[0m'
    boolean_to_text_and_color = {
        True: ('FOUND', '\x1b[6;30;42m'),
        False: ('NOT_FOUND', '\x1b[6;30;41m')
    }

    for atom_type in raw_response.keys():
        logger.info(f'{blue_bg}{"#" * 60} {atom_type.upper()} {"#" * (60 - len(atom_type))}{eol}')

        for atom in raw_response[atom_type]:
            found = atom.get('threat_found', False)
            text, color = boolean_to_text_and_color[found]
            logger.info(f'{atom_type} {atom["atom_value"]} hashkey: {atom["hashkey"]} {color} {text} {eol}')

        logger.info('')


if __name__ == '__main__':
    sys.exit(main())
