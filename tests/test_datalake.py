import responses
from datalake_scripts import Datalake
import pytest

threats = [
    'mayoclinic.org',
    'commentcamarche.net',
    'gawker.com'
]


@pytest.fixture
@responses.activate
def datalake():
    url = 'https://datalake.cert.orangecyberdefense.com/api/v2/auth/token/'

    auth_response = {
        "access_token": "12345",
        "refresh_token": "123456"
    }

    responses.add(responses.POST, url,
                  json=auth_response, status=200)

    return Datalake(username='lesid', password='getget')


def test_token_auth(datalake):
    auth_response = {
        "access_token": "12345",
        "refresh_token": "123456"
    }
    assert datalake._lookup_threats_api.tokens[0] == f"Token {auth_response['access_token']}"
    assert datalake._lookup_threats_api.tokens[1] == f"Token {auth_response['refresh_token']}"


@responses.activate
def test_lookup_threat(datalake):
    resp_json = {'atom_type': 'domain',
                 'content': {'domain_content': {'atom_value': 'mayoclinic.org',
                                                'depth': 1,
                                                'domain': 'mayoclinic.org',
                                                'notify': True,
                                                'tld': 'org'}},
                 'first_seen': '2021-04-03T21:10:33Z',
                 'hashkey': '13166b76877347b83ec060f44b847071',
                 'href_graph': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/13166b76877347b83ec060f44b847071/graph/',
                 'href_history': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats-history/13166b76877347b83ec060f44b847071/',
                 'href_threat': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/13166b76877347b83ec060f44b847071/',
                 'last_updated': '2021-05-12T10:55:49Z',
                 'metadata': {'virustotal_url_feed': {'last_analysis_stats': {'harmless': 80,
                                                                              'malicious': 0,
                                                                              'suspicious': 0,
                                                                              'timeout': 0,
                                                                              'undetected': 7},
                                                      'permalink': 'https://www.virustotal.com/gui/url/af017a61fedd9c7002db06689a43b28fb14ef76d590f67694506bfc0815fd667',
                                                      'positives': 0,
                                                      'total': 87}},
                 'scores': [{'score': {'reliability': 16, 'risk': 0}, 'threat_type': 'malware'},
                            {'score': {'reliability': 16, 'risk': 0},
                             'threat_type': 'phishing'},
                            {'score': {'reliability': 16, 'risk': 0}, 'threat_type': 'spam'}],
                 'sources': [{'count': 2,
                              'first_seen': '2021-04-03T21:10:33Z',
                              'last_updated': '2021-05-12T10:55:49Z',
                              'max_depth': 1,
                              'min_depth': 1,
                              'source_id': 'virustotal_url_feed (notify)',
                              'source_policy': {'source_categories': ['threatintell',
                                                                      'reputation',
                                                                      'antivirus'],
                                                'source_conditions': 'yes',
                                                'source_name_display': ['restricted_internal'],
                                                'source_references_conditions': 'no resell',
                                                'source_uses': ['notify']},
                              'tlp': 'amber'}],
                 'system_first_seen': '2021-04-05T22:02:33Z',
                 'system_last_updated': '2021-05-12T11:56:24Z',
                 'tags': []}
    extractor_response = {
        "found": 1,
        "not_found": 0,
        "results": {
            "domain": [
                "mayoclinic.org"
            ]
        }
    }
    responses.add(responses.POST, datalake._post_engine_atom_values_extractor.url,
                  json=extractor_response, status=200)
    responses.add(responses.GET, datalake._lookup_threats_api.url,
                  json=resp_json, status=200)

    lookup_response = datalake.lookup_threat(threats[0])

    assert lookup_response == resp_json


@responses.activate
def test_bulk_lookup_threats(datalake):
    extractor_response = {
        "found": 1,
        "not_found": 0,
        "results": {
            "domain": [
                "mayoclinic.org"
            ]
        }
    }
    responses.add(responses.POST, datalake._post_engine_atom_values_extractor.url,
                  json=extractor_response, status=200)

    bulk_resp = {'domain': [{'atom_value': 'mayoclinic.org',
                             'hashkey': '13166b76877347b83ec060f44b847071',
                             'threat_details': {'atom_type': 'domain',
                                                'content': {'domain_content': {'atom_value': 'mayoclinic.org',
                                                                               'depth': 1,
                                                                               'domain': 'mayoclinic.org',
                                                                               'notify': True,
                                                                               'tld': 'org'}},
                                                'first_seen': '2021-04-03T21:10:33Z',
                                                'hashkey': '13166b76877347b83ec060f44b847071',
                                                'href_graph': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/13166b76877347b83ec060f44b847071/graph/',
                                                'href_history': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats-history/13166b76877347b83ec060f44b847071/',
                                                'href_threat': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/13166b76877347b83ec060f44b847071/',
                                                'last_updated': '2021-05-12T10:55:49Z',
                                                'metadata': {'virustotal_url_feed': {'last_analysis_stats': {'harmless': 80,
                                                                                                             'malicious': 0,
                                                                                                             'suspicious': 0,
                                                                                                             'timeout': 0,
                                                                                                             'undetected': 7},
                                                                                     'permalink': 'https://www.virustotal.com/gui/url/af017a61fedd9c7002db06689a43b28fb14ef76d590f67694506bfc0815fd667',
                                                                                     'positives': 0,
                                                                                     'total': 87}},
                                                'scores': [{'score': {'reliability': 16,
                                                                      'risk': 0},
                                                            'threat_type': 'malware'},
                                                           {'score': {'reliability': 16,
                                                                      'risk': 0},
                                                            'threat_type': 'phishing'},
                                                           {'score': {'reliability': 16,
                                                                      'risk': 0},
                                                            'threat_type': 'spam'}],
                                                'sources': [{'count': 2,
                                                             'first_seen': '2021-04-03T21:10:33Z',
                                                             'last_updated': '2021-05-12T10:55:49Z',
                                                             'max_depth': 1,
                                                             'min_depth': 1,
                                                             'source_id': 'virustotal_url_feed '
                                                             '(notify)',
                                                             'source_policy': {'source_categories': ['threatintell',
                                                                                                     'reputation',
                                                                                                     'antivirus'],
                                                                               'source_conditions': 'yes',
                                                                               'source_name_display': ['restricted_internal'],
                                                                               'source_references_conditions': 'no '
                                                                               'resell',
                                                                               'source_uses': ['notify']},
                                                             'tlp': 'amber'}],
                                                'system_first_seen': '2021-04-05T22:02:33Z',
                                                'system_last_updated': '2021-05-12T11:56:24Z',
                                                'tags': []},
                             'threat_found': True},
                            {'atom_value': 'gawker.com',
                             'hashkey': '664d2e13bff4ac355c94b4f62ac0b92a',
                             'threat_found': False}
                             ]}

    responses.add(responses.POST, datalake._bulk_lookup_threats_api.url,
                  json=bulk_resp, status=200)

    assert datalake.bulk_lookup_threats(threats) == bulk_resp