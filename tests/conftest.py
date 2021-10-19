import os


def pytest_sessionstart(session):
    os.environ["OCD_DTL_REQUESTS_PER_QUOTA_TIME"] = "10000"  # Disable the throttler during tests
    os.environ["OCD_DTL_MAX_BACK_OFF_TIME"] = "0.01"  # waiting should be minimal
