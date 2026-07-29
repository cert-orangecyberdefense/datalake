"""User-Agent string builder for outbound Endpoint HTTP calls."""

import os

# this weird code block is to maintain python 3.7 compatibility
try:
    from importlib.metadata import PackageNotFoundError, version
except ImportError:  # Python < 3.8
    from importlib_metadata import PackageNotFoundError, version

USER_AGENT_INTEGRATION_ENV = "OCD_DTL_USER_AGENT_INTEGRATION"


def _get_version() -> str:
    try:
        return version("datalake_scripts")
    except PackageNotFoundError:
        return "unknown"


def build_user_agent() -> str:
    base = f"datalake-python-sdk/{_get_version()}"
    integration = (os.getenv(USER_AGENT_INTEGRATION_ENV) or "").strip()
    if integration:
        return f"{integration} {base}"
    return base
