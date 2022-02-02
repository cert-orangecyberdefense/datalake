import pytest

from datalake_scripts.engines.get_engine import ThreatsSearch
from datalake_scripts.engines.post_engine import CommentsPost, BulkSearch
from tests.common.fixture import token_manager, TestData  # noqa needed fixture import


def test_auth(token_manager):
    assert token_manager.url_token == 'https://datalake.com/api/v42/auth/token/'
    assert token_manager.access_token == 'Token access_token'
    assert token_manager.refresh_token == 'Token refresh_token'


@pytest.mark.parametrize("engine,expected_url", [
    (ThreatsSearch, 'https://datalake.com/api/v42/mrti/threats/'),
    (BulkSearch, 'https://datalake.com/api/v42/mrti/bulk-search/'),
    (CommentsPost, 'https://datalake.com/api/v42/mrti/threats/{hashkey}/comments/'),
])
def test_engine(token_manager, engine, expected_url):
    engine = engine(TestData.TEST_CONFIG, environment=TestData.TEST_ENV, token_manager=token_manager)
    assert engine.url == expected_url
