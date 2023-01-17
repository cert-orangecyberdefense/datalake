import sys

from datalake.common.config import Config
from datalake.common.logger import logger, configure_logging
from datalake.common.token_manager import TokenManager
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.engines.get_engine import ThreatsSearch
from datalake_scripts.helper_scripts.utils import load_list, save_output


def main(override_args=None):
    """Method to start the script"""
    logger.debug(f'START: get_threats_by_hashkey.py')

    # Load initial args
    parser = BaseScripts.start('Retrieve threats (as Json) from a list of ids (hashkeys)')
    parser.add_argument(
        'hashkeys',
        help='hashkeys of the threats to retreive',
        nargs='*',
    )
    parser.add_argument(
        '-i',
        '--input_file',
        help='list of threats ids (hashkeys) that need to be retrieved',
    )
    parser.add_argument(
        '--lost',
        help='saved hashes that were not found',
    )
    if override_args:
        args = parser.parse_args(override_args)
    else:
        args = parser.parse_args()
    configure_logging(args.loglevel)

    if not args.hashkeys and not args.input_file:
        parser.error("either a hashkey or an input_file is required")
    threats_list = load_list(args.input_file) if args.input_file else args.hashkeys
    logger.debug(f'TOTAL: {len(threats_list)} threats found')

    # Load api_endpoints and tokens
    endpoint_config = Config().load_config()
    token_manager = TokenManager(endpoint_config, environment=args.env)
    search_engine_threats = ThreatsSearch(endpoint_config, args.env, token_manager)
    list_threats, list_lost_hashes = search_engine_threats.get_json(threats_list)

    if args.output:
        save_output(args.output, list_threats)
        logger.debug(f'Threats JSON saved in {args.output}\n')
    if args.lost:
        save_output(args.lost, list_lost_hashes)
        logger.debug(f'Threats lost saved in {args.lost}\n')
    logger.debug(f'END: get_threats_by_hashkey.py')


if __name__ == '__main__':
    sys.exit(main())
