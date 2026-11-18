import logging
from itertools import zip_longest
from typing import List

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from datalake.common.logger import THEME, console as err_console
from datalake_scripts.common.rendering.base import Progress, Renderer
from datalake_scripts.helper_scripts.output_builder import format_threats_output


class Spinner(Progress):
    """Animated spinner on stderr, persisting a ✔ / ✖ line once the step is over"""

    def __init__(self, text: str):
        self.text = text
        self._status = err_console.status(escape(text), spinner="dots")

    def __enter__(self) -> "Spinner":
        self._status.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._status.stop()
        mark = "[bold green]✔[/]" if exc_type is None else "[bold red]✖[/]"
        err_console.print(f"{mark} {escape(self.text)}")
        return False

    def update(self, text: str):
        self.text = text
        self._status.update(escape(text))


class RichRenderer(Renderer):
    """Colored output with spinners and tables, used when running in a terminal"""

    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self.out = Console(theme=THEME)  # results go to stdout

    def progress(self, text: str) -> Progress:
        if not self.logger.isEnabledFor(logging.INFO):  # --quiet
            return super().progress(text)
        return Spinner(text)

    def item_status(self, value: str, status: str, prefix: str = ""):
        self.logger.info(f"{prefix}{value}: {status}")

    def json(self, data, sort_keys: bool = False):
        self.out.print_json(data=data, indent=4, sort_keys=sort_keys)

    def user_info(self, data: dict):
        self.json(data)

    def threats_from_query_hash(self, response: dict, one_threat_per_line: bool):
        if one_threat_per_line:
            print(format_threats_output(response, one_threat_per_line=True))
        else:
            self.json(response, sort_keys=True)

    def bulk_lookup(self, response, output_format: str, search_url: str):
        if output_format == "json":
            self.json(response, sort_keys=True)
            return
        if output_format == "csv":
            print(response)
            return

        results, search_hashkeys = self._split_lookup_response(response)
        for atom_type, atoms in results.items():
            table = self._table(title=f"[bold]{escape(atom_type.upper())}[/]")
            table.add_column("Atom value", overflow="fold")
            table.add_column("Hashkey", no_wrap=True)
            table.add_column("Status", justify="center", no_wrap=True)
            for atom in atoms:
                found = atom.get("threat_found", False)
                table.add_row(
                    Text(atom["atom_value"]),
                    Text(atom["hashkey"]),
                    self._status_badge(found, "FOUND", "NOT_FOUND"),
                )
            self.out.print(table)
            self.out.print()
        for line in self._search_links_lines(search_url, search_hashkeys):
            self.out.print(Text(line))

    def search_watch_diff(self, diff: dict):
        added = sorted(diff.get("added", []), key=lambda x: x[0])
        removed = sorted(diff.get("removed", []), key=lambda x: x[0])

        self.out.print()
        self.out.print(
            f"[bold]Threats summary from {escape(str(diff['from']))} to {escape(str(diff['to']))}[/]\n"
            f"Number of added items: [bold green]{len(added)}[/]\n"
            f"Number of removed items: [bold red]{len(removed)}[/]\n"
        )

        table = self._table()
        table.add_column(
            "Added (atom value - hash key)", style="green", overflow="fold"
        )
        table.add_column(
            "Removed (atom value - hash key)", style="red", overflow="fold"
        )
        for add, remove in zip_longest(added, removed, fillvalue=None):
            table.add_row(
                Text(f"{add[0]} - {add[1]}" if add else ""),
                Text(f"{remove[0]} - {remove[1]}" if remove else ""),
            )
        self.out.print(table)

    @staticmethod
    def _table(title: str = None) -> Table:
        return Table(title=title, title_justify="left", header_style="bold")

    @staticmethod
    def _status_badge(ok: bool, ok_label: str, ko_label: str) -> str:
        return f"[bold green]{ok_label}[/]" if ok else f"[bold red]{ko_label}[/]"
