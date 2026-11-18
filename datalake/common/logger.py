import logging
import sys
from typing import Optional

from rich.console import Console
from rich.highlighter import ReprHighlighter
from rich.logging import RichHandler
from rich.text import Text
from rich.theme import Theme

from datalake.common.output_mode import rich_output_enabled

logger = logging.getLogger("OCD_DTL")

DEBUG_FORMAT = "%(name)s:%(levelname)-4s %(message)s"
INFO_FORMAT = "%(message)s"

THEME = Theme(
    {
        "repr.status_ok": "bold green",
        "repr.status_ko": "bold red",
    }
)

# Console used for everything that is not the actual result of a command
# (logs, spinners, progress). It writes on stderr like the plain logging handler.
# It must be shared by the log handler and the spinners so they don't overlap.
console = Console(stderr=True, theme=THEME)


class DatalakeHighlighter(ReprHighlighter):
    """Color the status keywords used by the library and the CLI (OK, FAILED, ...)"""

    highlights = ReprHighlighter.highlights + [
        r"(?P<status_ok>\b(OK|FOUND)\b)",
        r"(?P<status_ko>\b(KO|FAILED|NOT_FOUND|ERROR)\b)",
    ]


class DatalakeRichHandler(RichHandler):
    LEVEL_STYLES = {
        logging.WARNING: "yellow",
        logging.ERROR: "bold red",
        logging.CRITICAL: "bold white on red",
    }

    def __init__(self, loglevel: int):
        is_debug = loglevel == logging.DEBUG
        super().__init__(
            console=console,
            highlighter=DatalakeHighlighter(),
            show_time=is_debug,
            show_level=is_debug,
            show_path=is_debug,
            markup=False,
            rich_tracebacks=True,
        )

    def render_message(self, record: logging.LogRecord, message: str) -> Text:
        text = super().render_message(record, message)
        style = self.LEVEL_STYLES.get(record.levelno)
        if style:
            text.stylize_before(style)
        return text


class SimpleHandler(logging.StreamHandler):
    """Plain, non wrapped output on stderr, used for scripted usages"""

    def __init__(self, loglevel: int):
        super().__init__(sys.stderr)
        self.setFormatter(
            logging.Formatter(
                DEBUG_FORMAT if loglevel == logging.DEBUG else INFO_FORMAT
            )
        )


_handler: Optional[logging.Handler] = None


def _build_handler(loglevel: int) -> logging.Handler:
    handler_class = DatalakeRichHandler if rich_output_enabled() else SimpleHandler
    return handler_class(loglevel)


def configure_logging(loglevel: int):
    global _handler
    if _handler is not None:
        logger.removeHandler(_handler)
    _handler = _build_handler(loglevel)
    logger.addHandler(_handler)
    logger.setLevel(loglevel)

    logger.debug(f"Logging configured with level {str(loglevel)}")

    return logger
