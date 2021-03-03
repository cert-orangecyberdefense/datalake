import pytest


@pytest.fixture
def tokens():
    """Fake tokens to be used in mocked requests"""
    return ['access token', 'refresh token']
