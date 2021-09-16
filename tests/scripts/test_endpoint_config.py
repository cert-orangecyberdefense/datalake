import pytest

from datalake_scripts.common.token_manager import TokenGenerator
from datalake_scripts.engines.get_engine import LookupThreats, ThreatsSearch
from datalake_scripts.engines.post_engine import CommentsPost, ThreatsPost, ScorePost, TagsPost, BulkSearch

TEST_ENV = 'my_env'
TEST_CONFIG = {
    'main': {
        TEST_ENV: 'https://datalake.com/api/'
    },
    'endpoints': {
        'bulk-search': 'mrti/bulk-search/',
        'threats': 'mrti/threats/',
        'threats-manual': 'mrti/threats-manual/',
        'token': 'auth/token/',
        "advanced-search": "mrti/advanced-queries/threats/",
        'refresh_token': 'auth/refresh-token/',
        'lookup': 'mrti/threats/lookup/',
        'comment': 'mrti/threats/{hashkey}/comments/',
        'tag': 'mrti/threats/{hashkey}/tags/',
    },
    'api_version': 'v42/'
}


def test_auth():
    engine = TokenGenerator(TEST_CONFIG, environment=TEST_ENV)
    assert engine.url_token == 'https://datalake.com/api/v42/auth/token/'


@pytest.mark.parametrize("engine,expected_url", [
    (LookupThreats, 'https://datalake.com/api/v42/mrti/threats/lookup/'),
    (ThreatsSearch, 'https://datalake.com/api/v42/mrti/threats/'),
    (BulkSearch, 'https://datalake.com/api/v42/mrti/bulk-search/'),
    (ThreatsPost, 'https://datalake.com/api/v42/mrti/threats-manual/'),
    (CommentsPost, 'https://datalake.com/api/v42/mrti/threats/{hashkey}/comments/'),
    (TagsPost, 'https://datalake.com/api/v42/mrti/threats/{hashkey}/tags/'),
    (ScorePost, 'https://datalake.com/api/v42/mrti/threats/'),
])
def test_engine(engine, expected_url):
    engine = engine(TEST_CONFIG, environment='my_env', tokens=[])
    assert engine.url == expected_url
