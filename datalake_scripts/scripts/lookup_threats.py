import sys
from collections import OrderedDict

from datalake import Datalake
from datalake_scripts.common.base_script import BaseScripts, InvalidHeader
from datalake_scripts.helper_scripts.output_builder import CsvBuilder
from datalake_scripts.helper_scripts.utils import (
    load_csv,
    load_list,
    save_output,
    parse_atom_type_or_exit,
)

boolean_to_text_and_color = {
    True: ("FOUND", "\x1b[6;30;42m"),
    False: ("NOT_FOUND", "\x1b[6;30;41m"),
}


def main(override_args=None):
    # Load initial args
    parser = BaseScripts.start("Submit a new threat to Datalake from a file")
    required_named = parser.add_argument_group("required arguments")
    csv_control = parser.add_argument_group("CSV control arguments")

    parser.add_argument(
        "threats",
        help="threats to lookup",
        nargs="*",
    )
    parser.add_argument(
        "-i",
        "--input",
        help="read threats to add from FILE",
    )
    parser.add_argument(
        "-td",
        "--threat_details",
        action="store_true",
        help="set it if you also want to have access to the threat details ",
    )
    parser.add_argument(
        "-ot",
        "--output-type",
        default="json",
        help="set it to the output type desired {json,csv}. Default is json if not specified",
    )
    required_named.add_argument(
        "-at",
        "--atom-type",
        help="set it to define the atom type",
        required=True,
    )
    csv_control.add_argument(
        "--is-csv",
        help="set it if the file input is a CSV",
        action="store_true",
    )
    csv_control.add_argument(
        "-d",
        "--delimiter",
        help="set to define the delimiter of the CSV file",
        default=",",
    )
    csv_control.add_argument(
        "-c",
        "--column",
        help="set the column number of the CSV file, starting at 1",
        type=int,
        default=1,
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    dtl.logger.debug(f"START: lookup_threats.py")

    if not args.threats and not args.input:
        parser.error("either a threat or an input file is required")

    if args.output_type:
        try:
            args.output_type = BaseScripts.output_type2header(args.output_type)
        except InvalidHeader as e:
            dtl.logger.exception(
                f"Exception raised while getting output type from headers # {str(e)}",
                exc_info=False,
            )
            exit(1)

    hashkey_only = not args.threat_details
    list_threats = list(args.threats) if args.threats else []
    if args.input:
        if args.is_csv:
            try:
                list_threats = list_threats + load_csv(
                    args.input, args.delimiter, args.column - 1
                )
            except ValueError as ve:
                dtl.logger.error(ve)
                exit()
        else:
            list_threats = list_threats + load_list(args.input)

    full_response = {}
    atom_type = parse_atom_type_or_exit(args.atom_type, dtl.logger)
    list_threats = list(
        OrderedDict.fromkeys(list_threats)
    )  # removing duplicates while preserving order
    for threat in list_threats:
        response = dtl.Threats.lookup(
            threat, atom_type=atom_type, hashkey_only=hashkey_only
        )
        found = response.get("threat_found", True)
        text, color = boolean_to_text_and_color[found]
        dtl.logger.info(
            "{}{} hashkey:{} {}\x1b[0m".format(color, threat, response["hashkey"], text)
        )
        full_response[threat] = response

    if args.output:
        if args.output_type == "text/csv":
            full_response = CsvBuilder.create_look_up_csv(
                full_response,
                args.atom_type,
                has_details=args.threat_details,
            )
        save_output(args.output, full_response)
        dtl.logger.debug(f"Results saved in {args.output}\n")
    dtl.logger.debug(f"END: lookup_threats.py")


if __name__ == "__main__":
    sys.exit(main())
