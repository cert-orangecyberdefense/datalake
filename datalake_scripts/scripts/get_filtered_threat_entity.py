import sys
import json
from datalake import Datalake, Output
from datalake_scripts.common.base_script import BaseScripts


def main(args=None):
    parser = BaseScripts.start("Get filtered and sorted list of threat entities.")
    # Add arguments as required by the subcommand
    parser.add_argument(
        "--threat-category-name", help="Name of the threat category", default=None
    )
    parser.add_argument("--alias", help="Alias for the threat entity", default=None)
    parser.add_argument(
        "--description", help="Description for the threat entity", default=None
    )
    parser.add_argument("-l", "--limit", help="Maximum number of item", default=None)
    parser.add_argument("--name", help="Name of the threat entity", default=None)
    parser.add_argument(
        "--offset", help="Index of the first item to return", default=None
    )
    parser.add_argument("--ordering", help="Ordering of the result", default=None)
    parser.add_argument("--stix_uuid", help="Filter by stix_uuid", default=None)
    parser.add_argument(
        "-t", "--tag", help="Filter Tag associated with threat entity", default=None
    )
    parser.add_argument(
        "-ot", "--output-type", help="Desired output type", default=None
    )

    if args is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(args)

    dtl = Datalake(env=args.env, log_level=args.loglevel)

    output_type = Output.JSON
    if args.output_type:
        try:
            output_type = Output[args.output_type.upper()]
        except KeyError:
            dtl.logger.error("Not supported output, please use either json or stix")
            exit(1)

    threat_entities = dtl.FilteredThreatEntity.get_filtered_and_sorted_list(
        threat_category_name=args.threat_category_name,
        alias=args.alias,
        description=args.description,
        limit=args.limit,
        name=args.name,
        offset=args.offset,
        ordering=args.ordering,
        stix_uuid=args.stix_uuid,
        tag=args.tag,
        output=output_type,
    )

    if args.output and threat_entities is not None:
        with open(args.output, "w") as f:
            json.dump(threat_entities, f, indent=4)
    elif threat_entities is not None:
        print(json.dumps(threat_entities, indent=4))


if __name__ == "__main__":
    sys.exit(main())
