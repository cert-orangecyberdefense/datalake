"""
Single source of truth for the output mode (rich or simple).

Rich output (colors, spinners, tables) is only used when the program runs
interactively, i.e. both stdout and stderr are attached to a terminal.
As soon as one of them is redirected (pipe, file, cron, CI...), the simple
output is used so that scripted usages keep a stable, plain text output.

Setting OCD_DTL_OUTPUT_MODE=simple forces the simple output.
"""

import os
import sys

OUTPUT_MODE_ENV = "OCD_DTL_OUTPUT_MODE"
SIMPLE_MODE = "simple"


def _isatty(stream) -> bool:
    try:
        return stream is not None and stream.isatty()
    except (AttributeError, ValueError):  # missing or closed stream
        return False


def rich_output_enabled() -> bool:
    if os.getenv(OUTPUT_MODE_ENV, "auto").strip().lower() == SIMPLE_MODE:
        return False
    return _isatty(sys.stdout) and _isatty(sys.stderr)
