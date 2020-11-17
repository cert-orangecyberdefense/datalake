import pytest

from datalake_scripts.helper_scripts.output_builder import CsvBuilder


@pytest.fixture
def csv_header():
    return 'hashkey,atom_type,atom_value_best_matching,atom_found'


@pytest.fixture
def csv_header_extended(csv_header):
    return f'{csv_header},events_number,first_seen,last_updated,' \
           'threat_types,ddos.score.risk,fraud.score.risk,hack.score.risk,leak.score.risk,malware.score.risk,' \
           'phishing.score.risk,scam.score.risk,spam.score.risk,sources,tags,href_graph,href_history,href_threat,' \
           'href_threat_webGUI'


def test_single_threat_no_details(csv_header):
    threat_type = 'as'
    api_response = {'48587': {'hashkey': '1b19ef78b0df6cd55fe894307d7fda8e', 'threat_found': True}}
    expected_response = [
        csv_header,
        '1b19ef78b0df6cd55fe894307d7fda8e,as,48587,True'
    ]

    assert CsvBuilder.create_look_up_csv(api_response, threat_type, has_details=False) == expected_response


def test_single_threat_with_details(csv_header_extended):
    threat_type = 'as'
    api_response = {
        '48587': {'sources': [{'count': 1,
                               'source_id': 'badips_apache',
                               'first_seen': '2020-10-24T05:30:38Z',
                               'last_updated': '2020-10-24T05:30:38Z'}, {
                                  'count': 3,
                                  'source_id': 'hybrid_analysis_public',
                                  'first_seen': '2020-10-18T02:01:17Z',
                                  'last_updated': '2020-10-18T02:10:24Z'}],
                  'system_last_updated': '2020-10-24T05:30:38Z',
                  'href_graph': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/graph/',
                  'href_threat': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/',
                  'atom_type': 'as', 'system_first_seen': '2020-04-09T11:59:30Z', 'content': {
                'as_content': {'allocation_date': '2008-12-12', 'owner': 'NET-0X2A-AS Datacentre _0x2a_, UA',
                               'registry': 'ripencc', 'country': 'UA', 'atom_value': 48587, 'asn': 48587}
            },
                  'tags': [],
                  'href_history': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats-history/1b19ef78b0df6cd55fe894307d7fda8e/',
                  'metadata': {},
                  'hashkey': '1b19ef78b0df6cd55fe894307d7fda8e',
                  'scores': [{'score': {'reliability': 1, 'risk': 0}, 'threat_type': 'ddos'},
                             {'score': {'reliability': 8, 'risk': 0}, 'threat_type': 'phishing'},
                             {'score': {'reliability': 8, 'risk': 0}, 'threat_type': 'spam'},
                             {'score': {'reliability': 1, 'risk': 0}, 'threat_type': 'scan'},
                             {'score': {'reliability': 1, 'risk': 0}, 'threat_type': 'hack'},
                             {'score': {'reliability': 10, 'risk': 1}, 'threat_type': 'malware'}],
                  'first_seen': '2013-03-13T14:37:35Z', 'last_updated': '2020-10-24T05:30:38Z'}
    }

    expected_response = [
        csv_header_extended,
        '1b19ef78b0df6cd55fe894307d7fda8e,as,48587,True,4,2013-03-13T14:37:35Z,2020-10-24T05:30:38Z,None,0,None,'
        '0,None,1,0,None,0,"badips_apache,hybrid_analysis_public",None,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/graph/,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats-history/1b19ef78b0df6cd55fe894307d7fda8e/,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/']

    assert CsvBuilder.create_look_up_csv(api_response, threat_type, has_details=True) == expected_response


def test_multiple_threats_no_details(csv_header):
    threat_type = 'as'
    api_response = {'48587': {'hashkey': '1b19ef78b0df6cd55fe894307d7fda8e', 'threat_found': True},
                    '48588': {'hashkey': '49b565d2fddc6861e6c5c236f065504d', 'threat_found': False}}
    expected_response = [
        csv_header,
        '1b19ef78b0df6cd55fe894307d7fda8e,as,48587,True',
        '49b565d2fddc6861e6c5c236f065504d,as,48588,False'
    ]

    assert CsvBuilder.create_look_up_csv(api_response, threat_type, has_details=False) == expected_response


def test_multiple_threats_with_details(csv_header_extended):
    threat_type = 'as'
    api_response = {
        '48587': {'sources': [{'count': 1, 'source_id': 'badips_apache',
                               'first_seen': '2020-10-24T05:30:38Z',
                               'last_updated': '2020-10-24T05:30:38Z'}, {
                                  'count': 3, 'source_id': 'hybrid_analysis_public',
                                  'first_seen': '2020-10-18T02:01:17Z',
                                  'last_updated': '2020-10-18T02:10:24Z'}],
                  'system_last_updated': '2020-10-24T05:30:38Z',
                  'href_graph': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/graph/',
                  'href_threat': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/',
                  'atom_type': 'as', 'system_first_seen': '2020-04-09T11:59:30Z', 'content': {
                'as_content': {'allocation_date': '2008-12-12', 'owner': 'NET-0X2A-AS Datacentre _0x2a_, UA',
                               'registry': 'ripencc', 'country': 'UA', 'atom_value': 48587, 'asn': 48587}}, 'tags': [],
                  'href_history': 'https://ti.extranet.mrti-center.com/api/v2/mrti/threats-history/1b19ef78b0df6cd55fe894307d7fda8e/',
                  'metadata': {},
                  'hashkey': '1b19ef78b0df6cd55fe894307d7fda8e',
                  'scores': [{'score': {'reliability': 1, 'risk': 0}, 'threat_type': 'ddos'},
                             {'score': {'reliability': 8, 'risk': 0}, 'threat_type': 'phishing'},
                             {'score': {'reliability': 8, 'risk': 0}, 'threat_type': 'spam'},
                             {'score': {'reliability': 1, 'risk': 0}, 'threat_type': 'scan'},
                             {'score': {'reliability': 1, 'risk': 0}, 'threat_type': 'hack'},
                             {'score': {'reliability': 10, 'risk': 1}, 'threat_type': 'malware'}],
                  'first_seen': '2013-03-13T14:37:35Z', 'last_updated': '2020-10-24T05:30:38Z'},
        '48588': {'hashkey': '49b565d2fddc6861e6c5c236f065504d', 'threat_found': False}
    }
    expected_response = [
        csv_header_extended,
        '1b19ef78b0df6cd55fe894307d7fda8e,as,48587,True,4,2013-03-13T14:37:35Z,2020-10-24T05:30:38Z,None,0,None,0,None,'
        '1,0,None,0,"badips_apache,hybrid_analysis_public",None,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/graph/,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats-history/1b19ef78b0df6cd55fe894307d7fda8e/,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/,'
        'https://ti.extranet.mrti-center.com/api/v2/mrti/threats/1b19ef78b0df6cd55fe894307d7fda8e/',
        '49b565d2fddc6861e6c5c236f065504d,as,48588,False,None,None,None,None,None,None,None,None,None,None,None,None,'
        'None,None,None,None,None,None'
    ]

    assert CsvBuilder.create_look_up_csv(api_response, threat_type, has_details=True) == expected_response
