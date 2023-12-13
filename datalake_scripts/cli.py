#!/usr/bin/env python3
import argparse
import sys
from datalake_scripts.scripts import (
    add_threats,
    get_threats_by_hashkey,
    edit_score,
    get_threats_from_query_hash,
    add_comments,
    lookup_threats,
    add_tags,
    get_query_hash,
    bulk_lookup_threats,
    advanced_search,
    get_atom_values,
    get_filtered_tag_subcategory,
    search_watch,
)


class Cli:
    CLI_NAME = "ocd-dtl"
    VERSION = "2.7.1"

    def __init__(self):
        parser = argparse.ArgumentParser(
            description="Cli to interact with OCD's Datalake",
            usage=f"{self.CLI_NAME} <command> [<args>]",
        )
        parser.add_argument(
            "--version", "-V", action="store_true", help="prints the current version"
        )
        subparsers = parser.add_subparsers(dest="command")

        # Add a subparser for each command
        self._add_command_subparser(subparsers, "add_threats", add_threats.main)
        self._add_command_subparser(
            subparsers, "get_threats", get_threats_by_hashkey.main
        )
        self._add_command_subparser(subparsers, "get_atom_values", get_atom_values.main)
        self._add_command_subparser(
            subparsers, "get_threats_from_query_hash", get_threats_from_query_hash.main
        )
        self._add_command_subparser(subparsers, "get_query_hash", get_query_hash.main)
        self._add_command_subparser(subparsers, "edit_score", edit_score.main)
        self._add_command_subparser(subparsers, "add_comments", add_comments.main)
        self._add_command_subparser(subparsers, "add_tags", add_tags.main)
        self._add_command_subparser(subparsers, "lookup_threats", lookup_threats.main)
        self._add_command_subparser(
            subparsers, "bulk_lookup_threats", bulk_lookup_threats.main
        )
        self._add_command_subparser(subparsers, "advanced_search", advanced_search.main)
        self._add_command_subparser(
            subparsers,
            "get_filtered_tag_subcategory",
            get_filtered_tag_subcategory.main,
        )
        self._add_command_subparser(subparsers, "search_watch", search_watch.main)

        args = parser.parse_args(sys.argv[1:2])

        if args.version:
            print(self.VERSION)
            exit(0)

        if not args.command:
            print("You must specify a command")
            parser.print_help()
            exit(1)

        # Call the subcommand method
        args.func(sys.argv[2:])

    def _add_command_subparser(self, subparsers, name, method):
        command_parser = subparsers.add_parser(name)
        command_parser.set_defaults(func=method)


def main():
    Cli()


if __name__ == "__main__":
    main()
