import sys
from datalake_scripts.common.base_script import BaseScripts
from datalake.common.logger import logger
from datalake import Datalake
from datalake.common.ouput import Output
from datalake_scripts.helper_scripts.utils import load_json, save_output


def main(override_args=None):
    parser = BaseScripts.start('Gets threats from given query body or query hash.', output_file_required=True)
    parser.add_argument(
        '-i',
        '--input',
        help='read query body from a json file'
    )
    parser.add_argument(
        '--query-hash',
        help='sets the query hash for the advanced search'
    )
    parser.add_argument(
        '-l',
        '--limit',
        help='defines how many items will be returned in one page slice. Accepted values: 0 to 5000, default is 20',
        type=int,
        default=20
    )
    parser.add_argument(
        '--offset',
        help='defines an index of the first requested item. Accepted values: 0 and bigger, default is 0.',
        type=int,
        default=0
    )
    parser.add_argument(
        '-ot',
        '--output-type',
        help='sets the output type desired {json, csv, stix, misp}. Default is json',
        default='json'
    )
    parser.add_argument(
        '--ordering',
        help='threat field to filter on. To sort the results by relevance (if any "search" is applied), just skip '
             'this field. To use the reversed order, use minus, i.e. --ordering="-last_updated" in your command line.'
    )

    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()
    logger.debug(f'START: advanced_search.py')
    if bool(args.input) == bool(args.query_hash):
        raise ValueError('Either an input file with a query body or a query hash needs to be provided.')
    try:
        output_type = Output[args.output_type.upper()]
    except KeyError:
        logger.error('Not supported output, please use json, stix, misp or csv')
        exit(1)

    dtl = Datalake(env=args.env, log_level=args.loglevel)
    if args.input:
        query_body = load_json(args.input)
        resp = dtl.AdvancedSearch.advanced_search_from_query_body(query_body, limit=args.limit, offset=args.offset,
                                                                  output=output_type, ordering=args.ordering)
    else:
        resp = dtl.AdvancedSearch.advanced_search_from_query_hash(args.query_hash, limit=args.limit, offset=args.offset,
                                                                  output=output_type, ordering=args.ordering)
    save_output(args.output, resp)
    logger.info(f'\x1b[0;30;42m OK: MATCHING THREATS SAVED IN {args.output} \x1b[0m')
    logger.debug(f'END: advanced_search.py')


if __name__ == '__main__':
    sys.exit(main())
