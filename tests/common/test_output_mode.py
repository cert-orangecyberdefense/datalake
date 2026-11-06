import logging
from types import SimpleNamespace

import pytest
from rich.logging import RichHandler

from datalake.common.logger import configure_logging
from datalake.common.output_mode import OUTPUT_MODE_ENV, rich_output_enabled
from datalake_scripts.common.rendering import (
    Progress,
    RichRenderer,
    SimpleRenderer,
    get_renderer,
)
from datalake_scripts.common.rendering.simple_renderer import ascii_table


class FakeStream:
    def __init__(self, tty: bool):
        self.tty = tty

    def isatty(self):
        return self.tty

    def write(self, _):
        pass

    def flush(self):
        pass


@pytest.fixture
def tty(monkeypatch):
    """Simulate stdout / stderr being (or not) attached to a terminal"""

    def _set(stdout: bool, stderr: bool = None):
        monkeypatch.delenv(OUTPUT_MODE_ENV, raising=False)
        monkeypatch.setattr("sys.stdout", FakeStream(stdout))
        monkeypatch.setattr(
            "sys.stderr", FakeStream(stdout if stderr is None else stderr)
        )

    return _set


@pytest.fixture
def dtl():
    return SimpleNamespace(
        logger=logging.getLogger("OCD_DTL"),
        Threats=SimpleNamespace(terminal_size=80),
    )


@pytest.mark.parametrize(
    "stdout_tty, stderr_tty, expected",
    [
        (True, True, True),
        (True, False, False),
        (False, True, False),
        (False, False, False),
    ],
)
def test_rich_output_requires_both_streams_to_be_tty(
    tty, stdout_tty, stderr_tty, expected
):
    tty(stdout_tty, stderr_tty)
    assert rich_output_enabled() is expected


def test_rich_output_can_be_disabled_by_env(tty, monkeypatch):
    tty(True)
    monkeypatch.setenv(OUTPUT_MODE_ENV, "simple")
    assert rich_output_enabled() is False


@pytest.mark.parametrize(
    "is_tty, expected_class", [(True, RichRenderer), (False, SimpleRenderer)]
)
def test_renderer_factory(tty, dtl, is_tty, expected_class):
    tty(is_tty)
    assert isinstance(get_renderer(dtl), expected_class)


def test_simple_logging_handler_when_not_a_tty(tty):
    tty(False)
    log = configure_logging(logging.INFO)
    assert not any(isinstance(h, RichHandler) for h in log.handlers)


def test_configure_logging_does_not_stack_handlers():
    log = configure_logging(logging.INFO)
    count = len(log.handlers)
    configure_logging(logging.INFO)
    assert len(log.handlers) == count


def test_simple_renderer_has_no_progress_display(dtl):
    progress = SimpleRenderer(dtl.logger, terminal_size=80).progress("working")
    assert type(progress) is Progress


def test_simple_renderer_item_status_keeps_legacy_layout(dtl, caplog):
    caplog.set_level(logging.INFO, logger="OCD_DTL")
    SimpleRenderer(dtl.logger, terminal_size=20).item_status("1.1.1.1", "OK")
    assert caplog.messages == ["1.1.1.1" + " " * 7 + "   OK  "]


def test_simple_renderer_bulk_lookup_keeps_legacy_layout(dtl, caplog):
    caplog.set_level(logging.INFO, logger="OCD_DTL")
    response = {
        "ip": [{"atom_value": "1.1.1.1", "hashkey": "abc", "threat_found": True}],
        "search_hashkey": ["q1"],
    }
    SimpleRenderer(dtl.logger, terminal_size=80).bulk_lookup(
        response, "table", "https://x/gui/?query_hash="
    )
    assert caplog.messages == [
        f'{"#" * 50} IP {"#" * 48}',
        "ip          1.1.1.1                        hashkey: abc       FOUND      ",
        "",
        "Results available here : https://x/gui/?query_hash=q1",
    ]
    assert "search_hashkey" in response  # the response is not altered


def test_ascii_table_legacy_layout():
    expected = (
        "+--------------------------------+---------------------------------+\n"
        "| Added (atom value - hash key)  | Removed (atom value - hash key) |\n"
        "+--------------------------------+---------------------------------+\n"
        "|          1.1.1.1 - h1          |          evil.com - h2          |\n"
        "+--------------------------------+---------------------------------+"
    )
    assert (
        ascii_table(SimpleRenderer.DIFF_HEADERS, [["1.1.1.1 - h1", "evil.com - h2"]])
        == expected
    )
