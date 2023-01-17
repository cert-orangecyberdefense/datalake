import json
import sys
import logging

from halo import Halo
from datalake import Datalake, AtomType, Output
from datalake.common.logger import logger
from datalake.common.utils import join_dicts, aggregate_csv_or_json_api_response
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import split_input_file, save_output
from urllib.parse import urlparse, urlsplit, urlunsplit

SUBCOMMAND_NAME = 'bulk_lookup_threats'
UNTYPED_ATOM_TYPE = 'untyped'
ATOM_TYPES_FLAGS = [atom_type.name.lower() for atom_type in AtomType]


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    parser = BaseScripts.start('Gets threats or hashkeys from given atom types and atom values.')
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

    output_type = Output.JSON
    if args.output_type:
        try:
            output_type = Output[args.output_type.upper()]
        except KeyError:
            logger.error('Not supported output, please use either json or csv')
            exit(1)
    # to gather all typed atoms passed by arguments and input files
    typed_atoms = {}

    # set validations flags regarding the presence or absence of cli arguments
    has_file = args.input is not None
    has_typed_atoms = False
    for flag in ATOM_TYPES_FLAGS:
        atom_values = getattr(args, flag)
        if atom_values is not None:
            typed_atoms[flag] = atom_values
            has_typed_atoms = True
    # validate that at least there is one untyped atom or one atom or one input file
    if (not has_typed_atoms and not has_file and not args.untyped_atoms) or (SUBCOMMAND_NAME in args.untyped_atoms):
        parser.error("you must provide at least one of following: untyped atom, atom type, input file.")

    # load api_endpoints and tokens
    dtl = Datalake(env=args.env, log_level=args.loglevel)
    spinner = None
    if logger.isEnabledFor(logging.INFO):
        spinner = Halo(text=f'Parsing input...', spinner='dots')
        spinner.start()
    hashkey_only = args.hashkey_only
    untyped_atoms = args.untyped_atoms or []
    size_limit = 100

    # Retrieve all atoms and try to type them first
    # process command line arguments inputs.
    untyped = []
    for untyped_atom in untyped_atoms:
        input_atom_type, atom = get_atom_type_from_filename(untyped_atom)
        if input_atom_type == UNTYPED_ATOM_TYPE:
            untyped.append(atom)
    typed_atoms_to_look_up = join_dicts(typed_atoms, lookup_atom_types(dtl, untyped))

    # process input files
    if has_file:
        for input_file in args.input:
            file_atom_type, filename = get_atom_type_from_filename(input_file)
            logger.debug(f'file {filename} was recognized as {file_atom_type}')
            if file_atom_type == UNTYPED_ATOM_TYPE:
                for atom_chunk in split_input_file(filename, size_limit):
                    untyped_atoms = atom_chunk
                    typed_atoms_to_look_up = join_dicts(lookup_atom_types(dtl, untyped_atoms), typed_atoms_to_look_up)
            else:
                for atom_chunk in split_input_file(filename, size_limit):
                    typed_atoms_to_look_up = join_dicts({file_atom_type: atom_chunk}, typed_atoms_to_look_up)

    # Query each atom type
    full_response = {}
    if spinner:
        spinner.text = f'Executing bulk search...'
    for atom_type, atoms in typed_atoms_to_look_up.items():
        response = dtl.Threats.bulk_lookup(
            atom_values=atoms,
            atom_type=AtomType[atom_type.upper()],
            hashkey_only=hashkey_only,
            output=output_type,
            return_search_hashkey=True
        )
        full_response = aggregate_csv_or_json_api_response(full_response, response)
    if spinner:
        spinner.succeed('Done.')
    if args.output:
        save_output(args.output, full_response)
        logger.debug(f'Results saved in {args.output}\n')
    else:
        pretty_print(full_response, args.output_type, args.env, dtl)
    logger.debug(f'END: lookup_threats.py')


def lookup_atom_types(dtl: Datalake, untyped_atoms):
    if not untyped_atoms:
        return {}

    response = dtl.Threats.atom_values_extract(untyped_atoms)
    if response['found'] == 0:
        logger.warning('none of your untyped atoms could be typed')

    # find out which atoms couldn't be typed to display them
    failed_to_type_atoms = response['not_found']
    if len(failed_to_type_atoms) > 0:
        logger.warning(f'\x1b[46m{"#" * 60} FAILED TO IDENTIFY ATOMS {"#" * 36}\x1b[46m')
        logger.warning('\n'.join(failed_to_type_atoms) + '\n')
    return response['results']


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

    logger.error(
        f'{filename} filename could not be treated `atomtype:path/to/file.txt`')
    exit(1)


def pretty_print(raw_response, stdout_format, env, dtl):
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

    search_hashkeys = raw_response.pop('search_hashkey', None)
    blue_bg = '\033[104m'
    eol = '\x1b[0m'
    boolean_to_text_and_color = {
        True: ('FOUND', '\x1b[6;30;42m'),
        False: ('NOT_FOUND', '\x1b[6;30;41m')
    }
    parsed_url = urlparse(dtl.Threats.endpoint_config['main'][env])
    base_url = f'{parsed_url.scheme}://{parsed_url.netloc}/gui/?query_hash='
    for atom_type in raw_response.keys():
        logger.info(
            f'\x1b[6;30;41m{blue_bg}{"#" * 50} {atom_type.upper()} {"#" * (50 - len(atom_type))}{eol}\x1b[0m')

        for atom in raw_response[atom_type]:
            found = atom.get('threat_found', False)
            text, color = boolean_to_text_and_color[found]
            logger.info(
                f'{atom_type : <11} {atom["atom_value"][:29] : <30} hashkey: {atom["hashkey"]} {color} {text :^15} {eol}')

        logger.info('')
    if search_hashkeys and len(search_hashkeys) <= 10:
        for search_hashkey in search_hashkeys:
            url = base_url + search_hashkey
            logger.info(f'Results available here : {url}')
    elif search_hashkeys and len(search_hashkeys) > 10:
        logger.info('Too many search hashkeys to display, check the output for the full list.')
    else:
        logger.info('No search hashkeys available for this lookup.')

if __name__ == '__main__':
    sys.exit(main())
