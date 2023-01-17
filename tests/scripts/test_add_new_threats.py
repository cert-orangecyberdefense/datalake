from datalake_scripts.scripts.add_threats import defang_threats, _build_threat_from_atom_type
from datalake import AtomType

def test_defanging():
    threats = ['https://threta.com', 'https://another.com', 'another.com', 'domain[.]com', 'www(.)domain(.)com',
               'https://andanother.com', 'http://FE80:0000:0000:0000:0202:B3FF:FE1E:8',
               'ftp://34.237.176.218/pub/daemon.php', 'sftp://34.237.176.218/pub/daemon.php',
               'ftps://34.237.176.218/pub/daemon.php', 'dfsdfsdf', 'http://a la mer', 'a la mer', 'meràboire',
               'çoulographe', '0.12.5.6']
    defanged = defang_threats(threats, 'url')
    planned_defanged = [
        'https://threta.com', 'https://another.com', 'http://another.com', 'http://domain.com',
        'http://www.domain.com', 'https://andanother.com',
        'http://FE80:0000:0000:0000:0202:B3FF:FE1E:8',
        'http://34.237.176.218/pub/daemon.php', 'https://34.237.176.218/pub/daemon.php',
        'https://34.237.176.218/pub/daemon.php', 'http://0.12.5.6'
    ]

    assert defanged == planned_defanged


def test_build_threat_from_atom_type():
    expected_file_atom = {
        'file_content': {
            'hashes': {
                'md5': 'd26351ba789fba3385d2382aa9d24908'
            },
            'external_analysis_link': ['https://someurl.co']
        }
    }
    output = _build_threat_from_atom_type('d26351ba789fba3385d2382aa9d24908', AtomType.FILE, ['https://someurl.co']).generate_atom_json()

    assert output == expected_file_atom