from tests.common.fixture import datalake  # noqa needed fixture import
from datalake import IpAtom, FileAtom, Hashes, Jarm, IpService
import warnings

jarm = Jarm('12/12/2012 12:12:12', 'some_fingerprint', False, 'some_malware')
ip_service = IpService(port=78, service_name='some_service', application='some_application', protocol='some_protocol')
ip_atom = IpAtom(
    ip_address='8.8.8.8',
    external_analysis_link=['https://some_url.co'],
    hostanme='some_host',
    ip_version=4,
    jarm=jarm,
    malware_family='some_malware',
    owner='owmer',
    peer_asns=[1, 2, 3],
    services=ip_service
)
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


def test_generate_atom_json_remove_unused_keys_for_sightings(datalake):
    expect_output = {
        'ip_list': [
            {
                'ip_address': '8.8.8.8'
            }
        ]
    }
    output = ip_atom.generate_atom_json(for_sightings=True)

    assert expect_output == output


def test_generate_atom_json(datalake):
    expect_output = {
        'ip_address': '8.8.8.8',
        'external_analysis_link': ['https://some_url.co'],
        'hostanme': 'some_host',
        'ip_version': 4,
        'jarm': {
            'calculated_at': '12/12/2012 12:12:12',
            'fingerprint': 'some_fingerprint',
            'malicious': False,
            'malware_family': 'some_malware'
        },
        'malware_family': 'some_malware',
        'owner': 'owmer',
        'peer_asns': [1, 2, 3],
        'services': {
            'port': 78,
            'service_name': 'some_service',
            'application': 'some_application',
            'protocol': 'some_protocol'
        }
    }
    output = ip_atom.generate_atom_json(for_sightings=False)

    assert expect_output == output


def test_generate_atom_json_nested_remove_unused_keys_for_sightings(datalake):
    expected_output = {
        'file_list': [
            {
                'hashes': {
                    'md5': 'd26351ba789fba3385d2382aa9d24908',
                    'sha1': 'a61e243f25b8b08661011869a53315363697a0f4',
                    'sha256': 'c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e',
                    'sha512': '01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944'
                }
            }
        ]
    }
    output = file_atom.generate_atom_json(for_sightings=True)

    assert expected_output == output


def test_generate_atom_json_nested(datalake):
    expected_output = {
        'hashes': {
            'md5': 'd26351ba789fba3385d2382aa9d24908',
            'sha1': 'a61e243f25b8b08661011869a53315363697a0f4',
            'sha256': 'c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e',
            'sha512': '01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944'
        },
        'external_analysis_link': 'some_external_url',
        'filesize': 666,
        'filetype': 'jpg',
        'file_url': 'some_url',
        'mimetype': 'some_mime',
        'filename': 'some_filename',
        'filepath': 'some/path'
    }
    output = file_atom.generate_atom_json(for_sightings=False)

    assert expected_output == output


def test_generate_atom_json_nested_remove_unused_keys_for_sightings_warning(datalake):
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        file_atom.generate_atom_json(for_sightings=True)
        assert len(w) == 1
