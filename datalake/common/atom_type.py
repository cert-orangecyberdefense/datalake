from enum import Enum
from dataclasses import dataclass, asdict

from typing import List, Dict


@dataclass
class Atom:
    """
    """
    pass

    def _factory(self, data):
        return {'content': dict(x for x in data if x[1] is not None)}

    def _sightings_factory(self, data):
        pass

    def generate_atom_json(self, for_sightings=False):
        """
        Utility method to returns a filtered json from the data given to the atom class for the API.
        """
        if for_sightings:
            return asdict(self, dict_factory=self._sightings_factory)
        return asdict(self, dict_factory=self._factory)


@dataclass
class Hashes:
    """
    At least one value is required
    """
    md5: str = None
    sha1: str = None
    sha256: str = None
    sha512: str = None
    ssdeep: str = None


@dataclass
class FileAtom(Atom):
    hashes: Hashes
    external_analysis_link: List[str] = None
    filesize: int = None
    filetype: str = None
    file_url: str = None
    mimetype: str = None
    filename: str = None
    filepath: str = None

    def _sightings_factory(self, data):
        allowed = ['hashes', 'md5', 'sha1', 'sha256', 'sha512']
        return {'file_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class AndroidApp:
    package_name: str
    app_name: str = None
    developer: str = None
    version_name: str = None
    permissions: str = None


@dataclass
class ApkAtom(Atom):
    android: AndroidApp
    hashes: Hashes
    external_analysis_link: List[str] = None
    filesize: int = None
    filetype: str = None
    file_url: str = None
    mimetype: str = None
    filename: str = None
    filepath: str = None

    def _sightings_factory(self, data):
        allowed = ['android', 'package_name', 'version_name', 'hashes', 'md5', 'sha1', 'sha256', 'sha512']
        return {'apk_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class AsAtom(Atom):
    asn: int
    external_analysis_link: List[str] = None
    allocation_date: str = None
    country: str = None
    malware_family: str = None
    owner: str = None
    registry: str = None

    def _sightings_factory(self, data):
        allowed = ['asn']
        return {'as_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class CcAtom(Atom):
    """
    number: minLength = 8  maxLength = 19
    """
    number: str
    external_analysis_link: List[str] = None
    bin: int = None
    brand: str = None
    cvx: int = None
    description: str = None
    expiry_date: str = None

    def _sightings_factory(self, data):
        allowed = ['number']
        return {'cc_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class CryptoAtom(Atom):
    """
    first_used and last_used expect the following datetime format: '%Y-%m-%dT%H:%M:%SZ'
    """
    crypto_address: str
    crypto_network: str
    external_analysis_link: List[str] = None
    number_of_transactions: int = None
    total_received: float = None
    total_sent: float = None
    first_used: str = None
    last_used: str = None

    def _sightings_factory(self, data):
        allowed = ['crypto_address', 'crypto_network']
        return {'crypto_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class CveAtom(Atom):
    """
    published_at expect the following datetime format: '%Y-%m-%dT%H:%M:%SZ'
    """
    cve_id: str
    cvss: int = None
    cwe: str = None
    external_analysis_link: List[str] = None
    published_at: str = None

    def _sightings_factory(self, data):
        allowed = ['cve_id']
        return {'cve_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class Jarm:
    calculated_at: str = None
    fingerprint: str = None
    malicious: bool = None
    malware_family: str = None


@dataclass
class DomainAtom(Atom):
    domain: str
    external_analysis_link: List[str] = None
    malware_family: str = None
    jarm: Jarm = None

    def _sightings_factory(self, data):
        allowed = ['domain']
        return {'domain_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


class EmailFlow(Enum):
    TO = 'to'
    FROM = 'from'


@dataclass
class EmailAtom(Atom):
    email: str
    email_flow: EmailFlow = None
    external_analysis_link: List[str] = None

    def _sightings_factory(self, data):
        allowed = ['email']
        return {'email_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class FqdnAtom(Atom):
    fqdn: str
    jarm: Jarm = None
    malware_family: str = None
    port: List[int] = None
    ns_list: List[str] = None
    external_analysis_link: List[str] = None

    def _sightings_factory(self, data):
        allowed = ['fqdn']
        return {'fqdn_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class IbanAtom(Atom):
    iban: str
    holder_name: str = None
    holder_address: str = None
    external_analysis_link: List[str] = None
    bic: str = None
    bank_name: str = None
    bank_address: str = None

    def _sightings_factory(self, data):
        allowed = ['iban']
        return {'iban_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class IpService:
    port: int
    service_name: str
    application: str = None
    protocol: str = None


@dataclass
class IpAtom(Atom):
    ip_address: str
    external_analysis_link: List[str] = None
    hostanme: str = None
    ip_version: int = None
    jarm: Jarm = None
    malware_family: str = None
    owner: str = None
    peer_asns: List[int] = None
    services: IpService = None

    def _sightings_factory(self, data):
        allowed = ['ip_address']
        return {'ip_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class IpRangeAtom(Atom):
    cidr: str
    country: str = None
    allocation_date: str = None
    external_analysis_link: List[str] = None
    owner: str = None
    owner_description: str = None
    registry: str = None

    def _sightings_factory(self, data):
        allowed = ['cidr']
        return {'ip_range_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class PasteAtom(Atom):
    url: str
    author: str = None
    title: str = None
    content: str = None
    external_analysis_link: List[str] = None

    def _sightings_factory(self, data):
        allowed = ['url']
        return {'paste_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class PhoneNumberAtom(Atom):
    """
    country: minLength = 2  maxLength = 2
    """
    company: str = None
    country: str = None
    external_analysis_link: List[str] = None
    international_phone_number: str = None
    national_phone_number: str = None

    def _sightings_factory(self, data):
        allowed = ['international_phone_number', 'national_phone_number']
        return {'phone_number_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class RegKeyAtom(Atom):
    path: str
    regkey_value: str = None
    hive: str = None
    external_analysis_link: List[str] = None

    def _sightings_factory(self, data):
        allowed = ['path']
        return {'regkey_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class SslAtom(Atom):
    hashes: Hashes
    issuer: str = None
    public_key: str = None
    serial_number: str = None
    signature: str = None
    signature_algorithm: str = None
    subject: str = None
    valid_not_after: str = None
    valid_not_before: str = None

    def _sightings_factory(self, data):
        allowed = ['hashes', 'md5', 'sha1', 'sha256', 'sha512']
        return {'ssl_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}


@dataclass
class UrlAtom(Atom):
    url: str
    malware_family: str = None
    jarm: Jarm = None
    http_headers: Dict[str, str] = None
    http_code: int = None
    external_analysis_link: List[str] = None
    reason: str = None

    def _sightings_factory(self, data):
        allowed = ['url']
        return {'url_list': [dict(x for x in data if x[1] is not None and x[0] in allowed)]}
