import pytest
import responses
from datalake import Datalake
from datetime import datetime
from tests.common.fixture import datalake  # noqa needed fixture import
from datalake import IpAtom, FileAtom, Hashes, Jarm, IpService,  SightingType, Visibility, ThreatType


jarm = Jarm('12/12/2012 12:12:12', 'some_fingerprint', True, 'some_malware')
ip_service = IpService(77, 'some_service', 'some_application', 'some_protocol')
ip_atom = IpAtom(
    '8.8.8.8',
    'https://some_url.co',
    'some_host',
    'ipv4',
    jarm,
    'some_malware',
    'owmer',
    [1, 2, 3],
    ip_service
)
ip_atom1 = IpAtom('9.9.9.9')
hashes = Hashes(
    md5='d26351ba789fba3385d2382aa9d24908',
    sha1='a61e243f25b8b08661011869a53315363697a0f4',
    sha256='c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e',
    sha512='01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944'
)
file_atom = FileAtom(
    hashes=hashes,
    filename='some_filename',
    file_url='some_url',
    external_analysis_link='some_external_url',
    filesize=666,
    filetype='jpg',
    mimetype='some_mime',
    filepath='some/path'
)
threat_types = [ThreatType.PHISHING, ThreatType.SCAM]
start = datetime.strptime('2021-05-10T16:20:23Z', "%Y-%m-%dT%H:%M:%SZ")
end = datetime.strptime('2021-05-11T16:20:23Z', "%Y-%m-%dT%H:%M:%SZ")

def test_prepare_sightings_payload(datalake):
    atoms = [file_atom, ip_atom, ip_atom1]
    sighting_type = SightingType.POSITIVE
    visibility = Visibility.PUBLIC
    count = 1
    threat_types = [ThreatType.SCAM]

    expected_payload = {
        'ip_list': [
            {'ip_address': '8.8.8.8'},
            {'ip_address': '9.9.9.9'}
        ],
        'file_list': [
            {
                'hashes': {
                    'md5': 'd26351ba789fba3385d2382aa9d24908',
                    'sha1': 'a61e243f25b8b08661011869a53315363697a0f4',
                    'sha256': 'c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e',
                    'sha512': '01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944'}
            }
        ],
        'start_timestamp': '2021-05-10T16:20:23Z',
        'end_timestamp': '2021-05-11T16:20:23Z',
        'visibility': 'PUBLIC',
        'type': 'POSITIVE',
        'count': 1,
        'threat_types': ['scam']
    }

    payload = datalake.Sightings._prepare_sightings_payload(
        atoms,
        None,
        start,
        end,
        sighting_type,
        visibility,
        count,
        threat_types
    )

    assert expected_payload == payload


@responses.activate
def test_submit_sightings(datalake):
    url = 'https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/sighting/'

    expected_res = {
        'count': 1,
        'end_timestamp': '2021-05-11T16:20:23Z',
        'relation_type': 'sighting',
        'reliability': 50,
        'sighting_version': 1,
        'sightings': {
            'file_list': [
                {
                    'hashes': {
                        'md5': 'd26351ba789fba3385d2382aa9d24908',
                        'sha1': 'a61e243f25b8b08661011869a53315363697a0f4',
                        'sha256': 'c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e',
                        'sha512': '01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944'
                    }
                }
            ],
            'ip_list': [
                {'ip_address': '8.8.8.8'},
                {'ip_address': '9.9.9.9'}
            ]
        },
        'source_context': {
            'source_id': 'org:45:public',
            'source_policy': {
                'source_uses': [
                    'commercial',
                    'internal',
                    'notify',
                    'sensitive'
                ]
            }
        },
        'start_timestamp': '2021-05-10T16:20:23Z',
        'tags': [],
        'threat_types': ['phishing', 'scam'],
        'timestamp_created': '2022-05-18T12:42:13Z',
        'type': 'positive',
        'uid': '1d67a120-8983-4909-a6f0-eec4a7673395'
    }

    responses.add(responses.POST, url, json=expected_res, status=200)

    res = datalake.Sightings.submit_sighting(
        start,
        end,
        SightingType.POSITIVE,
        Visibility.PUBLIC,
        1,
        threat_types,
        atoms=[ip_atom, ip_atom1, file_atom]
    )

    assert res == expected_res


def test_submit_sightings_no_atoms_no_hashkeys(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            Visibility.PUBLIC,
            1,
            threat_types
        )
    assert str(err.value) == 'Either threat hashkeys or list of atom objects is required.'


def test_submit_sightings_invalid_count(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            Visibility.PUBLIC,
            0,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom]
        )
    assert str(err.value) == 'count value minimum: 1'


def test_submit_sightings_bad_sighting_type(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            'positive',
            Visibility.PUBLIC,
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom]
        )
    assert str(err.value) == 'sighting_type has to be an instance of the SightingType class.'


def test_submit_sightings_no_threat_types(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            Visibility.PUBLIC,
            1,
            atoms=[ip_atom, ip_atom1, file_atom]
        )
    assert str(err.value) == 'For POSITIVE and NEGATIVE sightings "threat_types" field is required and has to be an instance of the Visibility class'


def test_submit_sightings_neutral_with_threat_types(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.NEUTRAL,
            Visibility.PUBLIC,
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom]
        )
    assert str(err.value) == "For NEUTRAL sightings, threat_types can't be passed."


def test_submit_sightings_bad_visibility(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            'public',
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom]
        )
    assert str(err.value) == 'visibility has to be an instance of the Visibility class.'


def test_submit_sightings_bad_atom(datalake):
    with pytest.raises(TypeError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            Visibility.PUBLIC,
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom, 'not_an_atom']
        )
    assert str(err.value) == 'atoms needs to be a list of Atom subclasses.'
