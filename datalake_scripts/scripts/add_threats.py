import json
import re
import sys

from collections import OrderedDict
from halo import Halo
from datalake import Datalake
from datalake import OverrideType, AtomType
from datalake.endpoints import Endpoint
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import (
    load_csv,
    load_list,
    save_output,
    parse_threat_types,
    flatten_list,
)
from datalake import (
    Hashes,
    FileAtom,
    AndroidApp,
    AsAtom,
    CryptoAtom,
    DomainAtom,
    EmailAtom,
    IpAtom,
    IpRangeAtom,
    PhoneNumberAtom,
    CertificateAtom,
    UrlAtom,
)


def hash_to_name(hash_):
    hash_list = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    return hash_list.get(len(hash_), "ssdeep")


def _build_threat_from_atom_type(value, atom_type, link=None):
    if atom_type == AtomType.AS:
        atom = AsAtom(external_analysis_link=link, asn=value)
    elif atom_type == AtomType.CRYPTO:
        address, network = value.split()
        atom = CryptoAtom(
            external_analysis_link=link, crypto_address=address, crypto_network=network
        )
    elif atom_type == AtomType.DOMAIN:
        atom = DomainAtom(external_analysis_link=link, domain=value)
    elif atom_type == AtomType.EMAIL:
        atom = EmailAtom(external_analysis_link=link, email=value)
    elif atom_type == AtomType.FILE:
        split_value = value.split(",")
        hash = split_value[0]
        package_name = (
            split_value[1] if len(split_value) > 1 else None
        )  # optional value for APK files
        hashes = Hashes(**{hash_to_name(hash): hash})
        if package_name:
            atom = FileAtom(
                external_analysis_link=link,
                hashes=hashes,
                android=AndroidApp(package_name),
            )
        else:
            atom = FileAtom(external_analysis_link=link, hashes=hashes)
    elif atom_type == AtomType.IP:
        atom = IpAtom(external_analysis_link=link, ip_address=value)
    elif atom_type == AtomType.IP_RANGE:
        atom = IpRangeAtom(external_analysis_link=link, cidr=value)
    elif atom_type == AtomType.PHONE_NUMBER:
        key = "international_phone_number"
        atom = PhoneNumberAtom(
            external_analysis_link=link, international_phone_number=value
        )
    elif atom_type == AtomType.CERTIFICATE:
        hashes = Hashes(**{hash_to_name(value): value})
        atom = CertificateAtom(external_analysis_link=link, hashes=hashes)
    elif atom_type == AtomType.URL:
        atom = UrlAtom(external_analysis_link=link, url=value)
    return atom


def defang_threats(threats, atom_type, logger=None):
    defanged = []
    # matches urls like http://www.website.com:444/file.html
    standard_url_regex = re.compile(
        r"^(https?://)[a-z0-9]+([\-.][a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(/.*)?$"
    )
    # matches urls like http://185.25.5.3:8080/result.php (ipv4 or ipv6)
    ip_url_regex = re.compile(
        r"^(https?://)[0-9a-zA-Z]{1,4}([.:][0-9a-zA-Z]{1,4}){3,7}(:[0-9]{1,5})?(/.*)?$"
    )
    for threat in threats:
        unmodified_threat = threat
        threat = threat.replace("[.]", ".")
        threat = threat.replace("(.)", ".")
        if atom_type == "url":
            if not threat.startswith("http"):
                if threat.startswith("hxxp"):
                    threat = threat.replace("hxxp", "http")
                elif threat.startswith("ftp"):
                    threat = threat.replace("ftp", "http")
                elif threat.startswith("sftp"):
                    threat = threat.replace("sftp", "https")
                else:
                    threat = "http://" + threat
            if not standard_url_regex.match(threat) and not ip_url_regex.match(threat):
                if logger is not None:
                    logger.warning(
                        f"'{unmodified_threat}' has been modified as '{threat}' but is still not recognized"
                        f" as an url. Skipping this line"
                    )
                continue
            if unmodified_threat != threat:
                if logger is not None:
                    logger.info(
                        f"'{unmodified_threat}' has been modified as '{threat}'"
                    )
        defanged.append(threat)
    return defanged


def main(override_args=None):
    """Method to start the script"""
    # Load initial args
    parser = BaseScripts.start("Submit a new threat to Datalake from a file")
    required_named = parser.add_argument_group("required arguments")
    csv_controle = parser.add_argument_group("CSV control arguments")
    required_named.add_argument(
        "-i",
        "--input",
        help="read threats to add from FILE",
        required=True,
    )
    required_named.add_argument(
        "-at",
        "--atom-type",
        help="set it to define the atom type",
        required=True,
    )
    csv_controle.add_argument(
        "--is-csv",
        help="set if the file input is a CSV",
        action="store_true",
    )
    csv_controle.add_argument(
        "-d",
        "--delimiter",
        help="set the delimiter of the CSV file",
        default=",",
    )
    csv_controle.add_argument(
        "-c",
        "--column",
        help="select column of the CSV file, starting at 1",
        type=int,
        default=1,
    )
    parser.add_argument(
        "-p",
        "--public",
        help="set the visibility to public",
        action="store_true",
    )
    parser.add_argument(
        "-w",
        "--whitelist",
        help="set it to define the added threats as whitelist",
        action="store_true",
    )
    parser.add_argument(
        "-tt",
        "--threat-types",
        nargs="+",
        help="choose specific threat types and their score, like: ddos 50 scam 15",
        default=[],
        action="append",
    )
    parser.add_argument(
        "-t",
        "--tag",
        nargs="+",
        help="add a list of tags",
        default=[],
    )
    parser.add_argument(
        "--link",
        help="add link as external_analysis_link",
        nargs="+",
    )
    parser.add_argument(
        "--lock",
        help="""sets override_type to lock. Scores won't be updated by the algorithm for three months. Newer IOCs with override_type lock can still override old lock changes.
            temporary: all values should override any values provided by older IOCs,
            but not newer ones.
            Default is "temporary" (all values should override any values provided by older IOCs)""",
        action="store_true",
    )
    parser.add_argument(
        "--no-bulk",
        help="force an api call for each threats, useful to retrieve the details of threats created",
        action="store_true",
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    dtl.logger.debug(f"START: add_new_threats.py")

    if not args.threat_types and not args.whitelist:
        parser.error("threat types is required if the atom is not for whitelisting")

    if args.lock:
        override_type = OverrideType.LOCK
    else:
        override_type = OverrideType.TEMPORARY

    if args.is_csv:
        try:
            list_new_threats = load_csv(args.input, args.delimiter, args.column - 1)
        except ValueError as ve:
            dtl.logger.error(ve)
            exit()
    else:
        list_new_threats = load_list(args.input)
        if not list_new_threats:
            raise parser.error("No atom found in the input file.")
    list_new_threats = defang_threats(list_new_threats, args.atom_type, dtl.logger)
    list_new_threats = list(
        OrderedDict.fromkeys(list_new_threats)
    )  # removing duplicates while preserving order
    args.threat_types = flatten_list(args.threat_types)
    threat_types = parse_threat_types(args.threat_types)
    atom_type = AtomType[args.atom_type.upper()]

    terminal_size = dtl.Threats.terminal_size
    if args.no_bulk:
        threat_response = []
        for threat in list_new_threats:
            try:
                atom = _build_threat_from_atom_type(threat, atom_type, args.link)
                res = dtl.Threats.add_threat(
                    atom=atom,
                    threat_types=threat_types,
                    override_type=override_type,
                    whitelist=args.whitelist,
                    public=args.public,
                    tags=args.tag,
                )
                threat_response.append(res)
                dtl.logger.info(
                    f'{threat.ljust(terminal_size - 6, " ")} \x1b[0;30;42m  OK  \x1b[0m'
                )
            except ValueError as ve:  # Wrong atom type most likely
                error_message = str(ve)
                threat_response.append(
                    {
                        "atom_value": threat,
                        "failed": True,
                        "error_message": error_message,
                    }
                )
                dtl.logger.info(
                    f'{threat.ljust(terminal_size - 6, " ")} '
                    f"\x1b[0;30;41m  KO  \x1b[0m"
                )
    else:
        try:
            spinner = Halo(text=f"Creating threats", spinner="dots")
            spinner.start()
            threat_response = dtl.Threats.add_threats(
                atom_list=list_new_threats,
                atom_type=atom_type,
                threat_types=threat_types,
                override_type=override_type,
                whitelist=args.whitelist,
                public=args.public,
                tags=args.tag,
                external_analysis_link=args.link,
            )
            spinner.succeed()
            failed = []
        except ValueError as ve:
            dtl.logger.error(ve)
            return

        failed_counter = 0
        created_counter = 0
        for batch_res in threat_response:
            failed.extend(batch_res["failed"])
            for success in batch_res["success"]:
                for val_created in success["created_atom_values"]:
                    created_counter += 1
                    dtl.logger.info(
                        f'{val_created.ljust(terminal_size - 6, " ")} \x1b[0;30;42m  OK  \x1b[0m'
                    )
        for failed_obj in failed:
            for failed_atom_val in failed_obj["failed_atom_values"]:
                failed_counter += 1
                dtl.logger.info(
                    f'Creation failed for value {failed_atom_val.ljust(terminal_size - 6, " ")} \x1b[0;30;4\
                1m  KO  \x1b[0m'
                )
        dtl.logger.info(
            f"Number of batches: {len(threat_response)}\n"
            f"Created threats: {created_counter}\n"
            f"Failed threat creation: {failed_counter}"
        )

    if args.output:
        save_output(args.output, json.dumps(threat_response))
        dtl.logger.debug(f"Results saved in {args.output}\n")
    dtl.logger.debug(f"END: add_new_threats.py")


if __name__ == "__main__":
    sys.exit(main())
