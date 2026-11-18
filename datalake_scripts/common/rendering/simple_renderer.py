import json
import logging
from itertools import zip_longest
from typing import List

from datalake_scripts.common.rendering.base import Renderer
from datalake_scripts.helper_scripts.output_builder import format_threats_output


class SimpleRenderer(Renderer):
    """
    Plain text output used for scripted usages (no tty).
    The layouts are kept identical to the historical output of the CLI so that
    customers parsing it are not disturbed.
    """

    DIFF_HEADERS = [
        "Added (atom value - hash key) ",
        "Removed (atom value - hash key)",
    ]

    def __init__(self, logger: logging.Logger, terminal_size: int):
        super().__init__(logger)
        self.terminal_size = terminal_size

    def item_status(self, value: str, status: str, prefix: str = ""):
        self.logger.info(
            f'{prefix}{value.ljust(self.terminal_size - 6, " ")}   {status}  '
        )

    def json(self, data):
        print(json.dumps(data, indent=4))

    def user_info(self, data: dict):
        print(data)

    def threats_from_query_hash(self, response: dict, one_threat_per_line: bool):
        self.logger.info(format_threats_output(response, one_threat_per_line))
        self.logger.info("Done")

    def bulk_lookup(self, response, output_format: str, search_url: str):
        if output_format == "json":
            self.logger.info(json.dumps(response, indent=4, sort_keys=True))
            return
        if output_format == "csv":
            self.logger.info(response)
            return

        results, search_hashkeys = self._split_lookup_response(response)
        for atom_type, atoms in results.items():
            self.logger.info(
                f'{"#" * 50} {atom_type.upper()} {"#" * (50 - len(atom_type))}'
            )
            for atom in atoms:
                status = "FOUND" if atom.get("threat_found", False) else "NOT_FOUND"
                self.logger.info(
                    f'{atom_type : <11} {atom["atom_value"][:29] : <30} hashkey: {atom["hashkey"]}  {status :^15} '
                )
            self.logger.info("")
        for line in self._search_links_lines(search_url, search_hashkeys):
            self.logger.info(line)

    def search_watch_diff(self, diff: dict):
        rows = []
        for add, remove in zip_longest(
            sorted(diff.get("added", []), key=lambda x: x[0]),
            sorted(diff.get("removed", []), key=lambda x: x[0]),
            fillvalue=["", ""],
        ):
            rows.append(
                [
                    f"{add[0]} - {add[1]}" if add else "",
                    f"{remove[0]} - {remove[1]}" if remove else "",
                ]
            )

        summary = f"\nThreats summary from {diff['from']} to {diff['to']}:\n"
        summary += f"Number of added items: {len(diff['added'])}\n"
        summary += f"Number of removed items: {len(diff['removed'])}\n"

        print(summary)
        print(ascii_table(self.DIFF_HEADERS, rows))


def _center(text: str, width: int) -> str:
    """Center a cell the same way the previous table library (prettytable) did"""
    excess = width - len(text)
    if excess % 2 and len(text) % 2 == 0:
        return " " * (excess // 2 + 1) + text + " " * (excess // 2)
    return " " * (excess // 2) + text + " " * (excess - excess // 2)


def ascii_table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [
        max([len(headers[i])] + [len(row[i]) for row in rows])
        for i in range(len(headers))
    ]
    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def format_row(cells):
        cells = (f" {_center(cell, width)} " for cell, width in zip(cells, widths))
        return "|" + "|".join(cells) + "|"

    lines = [separator, format_row(headers), separator]
    lines += [format_row(row) for row in rows]
    lines.append(separator)
    return "\n".join(lines)
