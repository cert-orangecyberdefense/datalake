#!/usr/bin/env python3

import argparse
import sys

from datalake_scripts.common.base_script import BaseScripts
from datalake_scripts.scripts import add_new_threats, get_threats_by_hashkey, edit_score, get_threats_from_query_hash, \
    add_new_comment_or_tags


class Cli:
    CLI_NAME = BaseScripts.PACKAGE_NAME

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='Cli to interact with OCD\'s Datalake',
            usage=f'''
            {self.CLI_NAME} <command> [<args>]

The most commonly used {self.CLI_NAME} commands are:
   add_threats     Submit a new threat to Datalake from a file
   get_threats     Retrieve threats (as Json) from a list of ids (hashkeys)
   edit_score      Edit scores of a specified list of ids (hashkeys)
            ''',
            epilog='Don\'t hesitate to leave a feedback on https://datalake.cert.orangecyberdefense.com/gui/ using the '
                   '"Add Feedback" button '
        )
        parser.add_argument('command', help='Subcommand to run', choices=self._list_commands_available())
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

    def add_threats(self):
        args = sys.argv[2:]
        add_new_threats.main(args)

    def get_threats(self):
        args = sys.argv[2:]
        get_threats_by_hashkey.main(args)

    def get_threats_from_query_hash(self):
        args = sys.argv[2:]
        get_threats_from_query_hash.main(args)

    def edit_score(self):
        args = sys.argv[2:]
        edit_score.main(args)

    def add_comment(self):
        args = sys.argv[2:]
        add_new_comment_or_tags.main(args)

    def _list_commands_available(self):
        method_list = []
        for method_name in dir(self):
            if method_name and method_name[0] != '_':
                try:
                    if callable(getattr(self, method_name)):
                        method_list.append(str(method_name))
                except:
                    method_list.append(str(method_name))
        return method_list


def main():  # Called in setup.py
    Cli()


if __name__ == '__main__':
    main()
