import json
import sys

from datalake_scripts.helper_scripts.utils import join_dicts
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.logger import logger
from datalake_scripts.engines.post_engine import BulkLookupThreats


# TODO
# it would be useful to add a flag for filtering not found atoms ? --only-found --only-not-found ?
# it would be useful to add a flag for pretty print the stdout ? like --pretty-print (take a look lookup)

SUBCOMMAND_NAME = 'bulk_lookup_threats'
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

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()
    logger.debug(f'START: bulk_lookup_threats.py')

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
    if not has_flag and not has_file:
        parser.error("you must provide at least one of following: atom type, input file.")

    # process input files
    if has_file:
        for input_file in args.input:
            input_file = get_atom_type_from_filename(input_file)
            if input_file:
                logger.debug(f'file {input_file[1]} was recognized as {input_file[0]}')
                typed_atoms.setdefault(input_file[0], []).extend(starter._load_list(input_file[1]))

    # load api_endpoints and tokens
    endpoints_config, main_url, tokens = starter.load_config(args)
    post_engine_bulk_lookup_threats = BulkLookupThreats(endpoints_config, args.env, tokens)

    response = post_engine_bulk_lookup_threats.bulk_lookup_threats(threats=typed_atoms, hashkey_only=args.hashkey_only)
    pretty_print(response)

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

    logger.error(f'{filename} filename could not be treated as input file, please specify its atom type')
    exit(1)


# TODO
    # when --atom-details flag is active we have to show all atom content here ? or only in the output file
def pretty_print(raw_response, stdout_format='human'):
    """
     takes the API raw response and format it for be printed as stdout
     stdout_format possible values {json, human}
    """
    if stdout_format == 'json':
        logger.info(json.dumps(raw_response, indent=4, sort_keys=True))

    if stdout_format == 'human':
        blue_bg = '\033[104m'
        eol = '\x1b[0m'
        boolean_to_text_and_color = {
            True: ('FOUND', '\x1b[6;30;42m'),
            False: ('NOT_FOUND', '\x1b[6;30;41m')
        }

        for atom_type in raw_response.keys():
            logger.info(f'{blue_bg}{"#" * 60} {atom_type.upper()} {"#" * (60 - len(atom_type))}{eol}')

            for atom in raw_response[atom_type]:
                found = atom['threat_found'] if 'threat_found' in atom.keys() else True
                text, color = boolean_to_text_and_color[found]
                logger.info(f'{atom_type} {atom["atom_value"]} hashkey: {atom["hashkey"]} {color} {text} {eol}')

            logger.info('')


if __name__ == '__main__':
    sys.exit(main())
