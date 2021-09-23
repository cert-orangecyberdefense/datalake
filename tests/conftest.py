import os


def pytest_sessionstart(session):
    os.environ["OCD_DTL_REQUESTS_PER_QUOTA_TIME"] = "10000"  # Disable the throttler during tests
