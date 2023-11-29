import sys
import json
from datalake_scripts.common.base_script import BaseScripts
from datalake.endpoints.filtered_tag_subcategory import FilteredTagSubcategory
from datalake.common.token_manager import TokenManager
from datalake.common.config import Config
import logging

# Configure logging to show only INFO level messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def main(args=None):
    parser = BaseScripts.start("Get filtered and sorted list of tag subcategories.")
    # Add arguments as required by the subcommand
    parser.add_argument("--category_name", help="Name of the category", default=None)
    parser.add_argument("--alias", help="Alias for the tag subcategory", default=None)
    parser.add_argument(
        "--description", help="Description for the tag subcategory", default=None
    )
    parser.add_argument("--limit", help="Maximum number of item", default=None)
    parser.add_argument("--name", help="Name of the tag subcategory", default=None)
    parser.add_argument(
        "--offset", help="Index of the first item to return", default=None
    )
    parser.add_argument("--ordering", help="Ordering of the result", default=None)
    parser.add_argument("--stix_uuid", help="Filter by stix_uuid", default=None)
    parser.add_argument(
        "--tag", help="Filter Tag associated with subcategory", default=None
    )

    if args is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(args)

    endpoint_config = Config().load_config()
    token_manager = TokenManager(endpoint_config, environment=args.env)

    fts = FilteredTagSubcategory(
        endpoint_config, environment=args.env, token_manager=token_manager
    )
    subcategories = fts.get_filtered_and_sorted_list(
        category_name=args.category_name,
        alias=args.alias,
        description=args.description,
        limit=args.limit,
        name=args.name,
        offset=args.offset,
        ordering=args.ordering,
        stix_uuid=args.stix_uuid,
        tag=args.tag,
    )

    if args.output and subcategories is not None:
        with open(args.output, "w") as f:
            json.dump(subcategories, f, indent=4)
    elif subcategories is not None:
        print(json.dumps(subcategories, indent=4))


if __name__ == "__main__":
    sys.exit(main())
