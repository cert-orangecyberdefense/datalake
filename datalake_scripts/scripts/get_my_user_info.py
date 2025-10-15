import sys

from datalake import Datalake
from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.helper_scripts.utils import save_output


def get_my_user_info_func(dtl: Datalake):
    response = dtl.MyAccount.me()
    return response


def main(override_args=None):
    """Method to start the script"""
    # Load initial args
    parser = BaseScripts.start("Gets details of the currently logged in user.")

    args = parser.parse_args(override_args or [])

    dtl = Datalake(env=args.env, log_level=args.loglevel)
    response = get_my_user_info_func(dtl)

    if args.output:
        save_output(args.output, response)
        dtl.logger.debug(f"Results saved in {args.output}\n")
    else:
        print(response)
    dtl.logger.debug(f"END: get_my_user_info.py")


if __name__ == "__main__":
    sys.exit(main())
