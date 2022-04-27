import json

import pytest
import responses

from datalake import Datalake, Output, AtomType, ThreatType, OverrideType
from tests.common.fixture import datalake  # noqa needed fixture import

atoms = [
    'mayoclinic.org',
    'commentcamarche.net',
    'gawker.com'
]

atom_values_extract_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/atom-values-extract/'


@responses.activate
def test_lookup_threat(datalake):
    lookup_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/lookup/' \
                 '?atom_value=mayoclinic.org&atom_type=domain&hashkey_only=False'
    # <editor-fold desc="resp_json">
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
    # </editor-fold>
    extractor_response = {
        "found": 1,
        "not_found": 0,
        "results": {
            "domain": [
                "mayoclinic.org"
            ]
        }
    }
    responses.add(responses.POST, atom_values_extract_url, json=extractor_response, status=200)
    responses.add(responses.GET, lookup_url, match_querystring=True, json=resp_json, status=200)

    lookup_response = datalake.Threats.lookup(atoms[0])

    assert lookup_response == resp_json


@responses.activate
def test_lookup_threat_invalid_output(datalake: Datalake):
    wrong_output = "123"
    with pytest.raises(ValueError) as err:
        datalake.Threats.lookup(atoms[0], output=wrong_output)
    assert str(err.value) == f'{wrong_output} output type is not supported. ' \
                             f'Outputs supported are: CSV, JSON, MISP, STIX'


@responses.activate
def test_lookup_threat_specific_output(datalake: Datalake):
    lookup_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/lookup/' \
                 '?atom_value=domain.net&atom_type=domain&hashkey_only=True'
    some_csv = "some csv"

    def request_callback(req):
        assert req.headers['Accept'] == 'text/csv'
        return 200, {'Content-Type': 'text/csv'}, some_csv

    responses.add_callback(
        responses.GET, lookup_url,
        callback=request_callback,
        match_querystring=True,
    )
    res = datalake.Threats.lookup(
        'domain.net',
        atom_type=AtomType.DOMAIN,
        hashkey_only=True,
        output=Output.CSV,
    )
    assert some_csv == res


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
    bulk_lookup_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/bulk-lookup/'
    responses.add(responses.POST, atom_values_extract_url, json=extractor_response, status=200)
    # <editor-fold desc="bulk_resp">
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
                                                'metadata': {
                                                    'virustotal_url_feed': {'last_analysis_stats': {'harmless': 80,
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
                                                                               'source_name_display': [
                                                                                   'restricted_internal'],
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
    # </editor-fold>

    responses.add(responses.POST, bulk_lookup_url, json=bulk_resp, status=200)
    assert datalake.Threats.bulk_lookup(atom_values=atoms) == bulk_resp


@responses.activate
def test_bulk_lookup_return_search_hashkey(datalake):
    extractor_response = {
        "found": 1,
        "not_found": 0,
        "results": {
            "domain": [
                "mayoclinic.org"
            ]
        }
    }
    bulk_lookup_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/bulk-lookup/'
    responses.add(responses.POST, atom_values_extract_url, json=extractor_response, status=200)
    # <editor-fold desc="bulk_resp">
    bulk_resp = {
        'domain': [
            {
                'access_permission': True,
                'atom_value': 'mayoclinic.org',
                'hashkey': '13166b76877347b83ec060f44b847071',
                'threat_found': True
            }
        ],
        'search_hashkey': '83fd935d302db70155cceddd09b15dfd'}  # </editor-fold>
    expected_resp = {
        'domain': [
            {
                'access_permission': True,
                'atom_value': 'mayoclinic.org',
                'hashkey': '13166b76877347b83ec060f44b847071',
                'threat_found': True
            }
        ],
        'search_hashkey': ['83fd935d302db70155cceddd09b15dfd']}
    responses.add(responses.POST, bulk_lookup_url, json=bulk_resp, status=200)
    assert datalake.Threats.bulk_lookup(atom_values=atoms, return_search_hashkey=True) == expected_resp


@responses.activate
def test_bulk_lookup_threats_on_typed_atoms(datalake):
    bulk_lookup_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/bulk-lookup/'

    bulk_resp = {'file': [{'uid': '123'}]}  # Only check the API response is returned as is

    responses.add(responses.POST, bulk_lookup_url, json=bulk_resp, status=200)
    assert datalake.Threats.bulk_lookup(atom_values=atoms, atom_type=AtomType.DOMAIN) == bulk_resp


@responses.activate
def test_bulk_lookup_threats_on_big_chunk_json(datalake):
    atom_values = [f'domain{i}.com' for i in range(10_000)]
    bulk_lookup_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/bulk-lookup/'

    def request_callback(req):
        assert req.headers['Accept'] == 'application/json'
        body = json.loads(req.body)
        assert len(body['domain']) == 100

        resp = {
            'domain': [
                {'atom_value': domain,
                 'hashkey': '664d2e13bff4ac355c94b4f62ac0b92a',
                 'threat_found': False}
                for domain in body['domain']
            ]
        }
        return 200, {'Content-Type': 'application/json'}, json.dumps(resp)

    responses.add_callback(
        responses.POST,
        bulk_lookup_url,
        callback=request_callback,
        match_querystring=True,
    )

    api_response = datalake.Threats.bulk_lookup(atom_values=atom_values, atom_type=AtomType.DOMAIN)

    assert len(responses.calls) == 100, 'big chunk of atoms should be split in multiple query for bulk lookup'
    assert len(api_response['domain']) == 10_000


@responses.activate
def test_bulk_lookup_threats_on_big_chunk_csv(datalake):
    atom_values = [f'domain{i}.com' for i in range(5_000)]
    bulk_lookup_url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/bulk-lookup/'
    header = 'hashkey,atom_type,atom_value,atom_value_best_matching,threat_found,events_number,first_seen,last_updated,threat_types,ddos.score.risk,fraud.score.risk,hack.score.risk,leak.score.risk,malware.score.risk,phishing.score.risk,scam.score.risk,scan.score.risk,spam.score.risk,sources,tags,href_graph,href_history,href_threat,href_threat_webGUI'

    def request_callback(req):
        assert req.headers['Accept'] == 'text/csv'
        body = json.loads(req.body)
        assert len(body['domain']) == 100

        resp = '\n'.join(
            [header] +
            [f'02bd4baae2bb8142509984c3c7574512,domain,{domain},,False,,,,,,,,,,,,,,,,,,,' for domain in body['domain']]
        )
        return 200, {'Content-Type': 'text/csv'}, resp

    responses.add_callback(
        responses.POST,
        bulk_lookup_url,
        callback=request_callback,
        match_querystring=True,
    )

    api_response = datalake.Threats.bulk_lookup(
        atom_values=atom_values,
        atom_type=AtomType.DOMAIN,
        output=Output.CSV,
    )

    assert len(responses.calls) == 50, 'big chunk of atoms should be split in multiple query for bulk lookup'
    csv_lines = api_response.split('\n')
    assert len(csv_lines) == 5_001
    assert csv_lines[0] == header


@responses.activate
def test_bulk_lookup_threat_invalid_output(datalake: Datalake):
    wrong_output = "123"
    with pytest.raises(ValueError) as err:
        datalake.Threats.bulk_lookup(atoms, output=wrong_output)
    assert str(err.value) == f'{wrong_output} output type is not supported. Outputs supported are: CSV, JSON'


@responses.activate
def test_bulk_lookup_threat_not_supported_output(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.bulk_lookup(atoms, output=Output.MISP)
    assert str(err.value) == f'MISP output type is not supported. Outputs supported are: CSV, JSON'


def test_edit_score_by_hashkeys_invalid_input(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.edit_score_by_hashkeys('not a list', None, None)
    assert str(err.value) == 'Hashkeys has to be a list of string'


def test_edit_score_by_hashkeys_empty_input(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.edit_score_by_hashkeys([], None, None)
    assert str(err.value) == 'Hashkeys has to be a list of string'


def test_edit_score_by_hashkeys_invalid_list(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.edit_score_by_hashkeys([1, 2, 3], None, None)
    assert str(err.value) == 'Hashkeys has to be a list of string'


def test_edit_score_by_hashkeys_empty_list_element(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.edit_score_by_hashkeys(['xxx-some-hashkey-xxx', ''], None, None)
    assert str(err.value) == 'Hashkeys has to be a list of string'


def test_edit_score_by_hashkeys_invalid_scores_threat_type(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.edit_score_by_hashkeys(['some_hashkey'], [{'threat_type': 'ddos'}])
    assert str(err.value) == 'Invalid threat_type input'


def test_edit_score_by_hashkeys_invalid_scores_score(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.edit_score_by_hashkeys(['some_hashkey'], [{'threat_type': ThreatType.DDOS, 'score': 999}])
    assert str(err.value) == 'Invalid score input, min: 0, max: 100'


def test_edit_score_bad_override_type(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        datalake.Threats.edit_score_by_hashkeys(['some_hashkey'], [{'threat_type': 'ddos'}], 'lock')
    assert str(err.value) == 'Invalid OverrideType input'


def test_add_threats_not_threat_types_not_whitelist(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        atom_list = ['100.100.100.1']
        datalake.Threats.add_threats(atom_list, AtomType.IP)
    assert str(err.value) == 'threat_types is required if the atom is not for whitelisting'


def test_add_threats_bad_override_type(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        atom_list = ['100.100.100.1']
        threat_types = [{'threat_type': ThreatType('ddos'), 'score': 5}]
        datalake.Threats.add_threats(atom_list, AtomType.IP, threat_types, 'lock')
    assert str(err.value) == 'Invalid OverrideType input'


def test_add_threats_bad_atom(datalake: Datalake):
    with pytest.raises(ValueError) as err:
        atom_list = ['100.100.100.1', '']
        threat_types = [{'threat_type': ThreatType('ddos'), 'score': 5}]
        datalake.Threats.add_threats(atom_list, AtomType.IP, threat_types, OverrideType.TEMPORARY)
    assert str(err.value) == 'Empty atom in atom_list'


@responses.activate
def test_add_threats_no_bulk(datalake: Datalake):
    url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats-manual/'
    ip = '11.11.111.1'
    resp = {
        'atom_type': 'ip',
        'atom_value': ip,
        'delivery_timestamp': '2021-12-23T15:57:23.450107+00:00',
        'hashkey': '3e3f43a23fadc97a5d4c72424d62f48a',
        'override_type': 'lock',
        'public': False,
        'threat_data': {
            'content': {
                'ip_content': {
                    'ip_address': ip, 'ip_version': 4}},
            'scores': [
                {
                    'score': {
                        'risk': 0
                    },
                    'threat_type': 'ddos'
                }
            ],
            'tags': ['test_tag', 'ocd']
        },
        'timestamp_created': '2021-12-23T15:57:23.306039+00:00',
        'user': {
            'email': 'user.user@email.com',
            'full_name': 'User USER', 'id': 0,
            'organization': {'id': 0, 'name': 'ORG', 'path_names': ['ORG']}
        },
        'uuid': '7447bbea-f9a8-44a4-8dca-fcdaa153d13b'
    }
    responses.add(responses.POST, url, json=resp, status=200)

    threat_types = [{'threat_type': ThreatType('ddos'), 'score': 0}]
    assert datalake.Threats.add_threat(ip, AtomType.IP, threat_types, OverrideType.TEMPORARY) == resp


@responses.activate
def test_add_threats_bulk(datalake: Datalake):
    url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-manual-threats/'
    atom_list = ['1.1.1.1', '1.1.1.2']
    task_uid = "5b127e18-b471-44ae-ae34-e616d74d63a9"
    hashkeys = ['498838952afbf8a47b68563206fbfca4', '4c7711a6bdbcb8626e3f07d4aaa317aa']
    post_resp = {
        "hashkeys": hashkeys,
        "task_uuid": task_uid
    }
    responses.add(responses.POST, url, json=post_resp, status=202)

    url = f'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/bulk-manual-threats/task/{task_uid}/'
    get_resp = {  # Returns the DONE response right away
        "atom_type": "ip",
        "atom_values": atom_list,
        "created_at": "2022-04-27T07:49:55.027385+00:00",
        "finished_at": "2022-04-27T07:49:58.186193+00:00",
        "hashkeys": hashkeys,
        "public": True,
        "queue_position": None,
        "started_at": "2022-04-27T07:49:57.919530+00:00",
        "state": "DONE",
        "tags": [],
        "user": {
            "email": "johnny.english@orange.com",
            "full_name": "johnny english",
            "id": 287,
            "organization": {"id": 4, "name": "OCD", "path_names": ["OCD"]}
        },
        "uuid": task_uid
    }
    responses.add(responses.GET, url, json=get_resp, status=200)

    threat_types = [{'threat_type': ThreatType('ddos'), 'score': 0}]
    assert datalake.Threats.add_threats(atom_list, AtomType.IP, threat_types, OverrideType.TEMPORARY) == [
        {
            'success': [
                {
                    'created_hashkeys': hashkeys,
                    'created_atom_values': ['1.1.1.1', '1.1.1.2']
                }
            ],
            'failed': []
        }
    ]
