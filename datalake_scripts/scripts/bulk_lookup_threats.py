import sys

from datalake import Datalake, AtomType, Output
from datalake.common.utils import join_dicts, aggregate_csv_or_json_api_response
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.common.rendering import get_renderer
from datalake_scripts.helper_scripts.utils import split_input_file, save_output
from urllib.parse import urlparse

SUBCOMMAND_NAME = "bulk_lookup_threats"
UNTYPED_ATOM_TYPE = "untyped"
ATOM_TYPES_FLAGS = [atom_type.name.lower() for atom_type in AtomType]


def lookup_atom_types(dtl: Datalake, untyped_atoms):
    if not untyped_atoms:
        return {}

    response = dtl.Threats._atom_values_extract(untyped_atoms)
    if response["found"] == 0:
        dtl.logger.warning("none of your untyped atoms could be typed")

    # find out which atoms couldn't be typed to display them
    failed_to_type_atoms = response["not_found"]
    if len(failed_to_type_atoms) > 0:
        dtl.logger.warning(f'{"#" * 60} FAILED TO IDENTIFY ATOMS {"#" * 36}')
        dtl.logger.warning("\n".join(failed_to_type_atoms) + "\n")
    return response["results"]


def get_atom_type_from_filename(filename, logger=None, input_delimiter=":"):
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

    if logger:
        logger.error(
            f"{filename} filename could not be treated `atomtype:path/to/file.txt`"
        )
    exit(1)


def gui_search_url(dtl: Datalake, env: str) -> str:
    """Url of a search in the Datalake GUI, to be completed with a search hashkey"""
    parsed_url = urlparse(dtl.Threats.endpoint_config["main"][env])
    return f"{parsed_url.scheme}://{parsed_url.netloc}/gui/?query_hash="


def main(override_args=None):
    """Method to start the script"""

    # Load initial args
    parser = BaseScripts.start(
        "Gets threats or hashkeys from given atom types and atom values."
    )
    supported_atom_types = parser.add_argument_group("Supported Atom Types")

    parser.add_argument(
        "untyped_atoms",
        help="untyped atom values to lookup. Useful when you do not know what is the atom type",
        nargs="*",
    )
    for atom_type in ATOM_TYPES_FLAGS:
        supported_atom_types.add_argument(
            f"--{atom_type}",
            action="append",
            help=f"set a single {atom_type} atom type with its value",
        )
    parser.add_argument(
        "-ad",
        "--atom-details",
        dest="hashkey_only",
        default=True,
        action="store_false",
        help="returns threats full details",
    )
    parser.add_argument(
        "-i",
        "--input",
        action="append",
        help="read threats to add from FILE. [atomtype:path/to/file.txt]",
    )
    parser.add_argument(
        "-ot",
        "--output-type",
        help="set to the output type desired {json,csv}. Default is json",
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    dtl.logger.debug(f"START: bulk_lookup_threats.py")

    output_type = Output.JSON
    if args.output_type:
        try:
            output_type = Output[args.output_type.upper()]
        except KeyError:
            dtl.logger.error("Not supported output, please use either json or csv")
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
    if (not has_typed_atoms and not has_file and not args.untyped_atoms) or (
        SUBCOMMAND_NAME in args.untyped_atoms
    ):
        parser.error(
            "you must provide at least one of following: untyped atom, atom type, input file."
        )

    # load api_endpoints and tokens

    renderer = get_renderer(dtl)
    with renderer.progress("Parsing input") as progress:
        hashkey_only = args.hashkey_only
        untyped_atoms = args.untyped_atoms or []
        size_limit = 100

        # Retrieve all atoms and try to type them first
        # process command line arguments inputs.
        untyped = []
        for untyped_atom in untyped_atoms:
            input_atom_type, atom = get_atom_type_from_filename(
                untyped_atom, dtl.logger
            )
            if input_atom_type == UNTYPED_ATOM_TYPE:
                untyped.append(atom)
        typed_atoms_to_look_up = join_dicts(
            typed_atoms, lookup_atom_types(dtl, untyped)
        )

        # process input files
        if has_file:
            for input_file in args.input:
                file_atom_type, filename = get_atom_type_from_filename(
                    input_file, dtl.logger
                )
                dtl.logger.debug(f"file {filename} was recognized as {file_atom_type}")
                if file_atom_type == UNTYPED_ATOM_TYPE:
                    for atom_chunk in split_input_file(filename, size_limit):
                        untyped_atoms = atom_chunk
                        typed_atoms_to_look_up = join_dicts(
                            lookup_atom_types(dtl, untyped_atoms),
                            typed_atoms_to_look_up,
                        )
                else:
                    for atom_chunk in split_input_file(filename, size_limit):
                        typed_atoms_to_look_up = join_dicts(
                            {file_atom_type: atom_chunk}, typed_atoms_to_look_up
                        )

        # Query each atom type
        full_response = {}
        progress.update("Executing bulk search")
        for atom_type, atoms in typed_atoms_to_look_up.items():
            response = dtl.Threats.bulk_lookup(
                atom_values=atoms,
                atom_type=AtomType[atom_type.upper()],
                hashkey_only=hashkey_only,
                output=output_type,
                return_search_hashkey=True,
            )
            full_response = aggregate_csv_or_json_api_response(full_response, response)
    if args.output:
        save_output(args.output, full_response)
        dtl.logger.debug(f"Results saved in {args.output}\n")
    else:
        renderer.bulk_lookup(
            full_response, args.output_type, gui_search_url(dtl, args.env)
        )
    dtl.logger.debug(f"END: lookup_threats.py")


if __name__ == "__main__":
    sys.exit(main())
