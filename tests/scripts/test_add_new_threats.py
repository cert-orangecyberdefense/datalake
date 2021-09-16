from datalake_scripts.scripts.add_threats import defang_threats


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
