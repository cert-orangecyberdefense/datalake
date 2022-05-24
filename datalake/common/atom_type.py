from enum import Enum
from abc import abstractmethod
from dataclasses import dataclass, asdict
from datalake.common.warn import Warn
from typing import List, Dict


@dataclass
class Atom:
    """
    Base class for atom types.
    """
    pass

    def _factory(self, data):
        return dict(x for x in data if x[1] is not None)

    @abstractmethod
    def _get_sightings_allowed_keys(self):
        pass

    @abstractmethod
    def _get_sightings_prefix(self):
        pass

    def _sightings_factory(self, data):
        allowed = self._get_sightings_allowed_keys()
        fact_dict = {}
        removed = False
        for x in data:
            if x[1] is not None:
                if x[0] in allowed:
                    fact_dict[x[0]] = x[1]
                else:
                    removed = True
        if removed:
            Warn.warning("Some keys aren't allowed for sightings and thus will be removed if you have set them. Check "
                         "the classes for information on which keys are allowed. To stop this warning from showing, "
                         "please set the IGNORE_SIGHTING_BUILDER_WARNING environment variable to True")
        return fact_dict

    def generate_atom_json(self, for_sightings=False):
        """
        Utility method to returns a filtered json from the data given to the atom class for the API.
        """
        if for_sightings:
            prefix = self._get_sightings_prefix()
            return {f'{prefix}_list': [asdict(self, dict_factory=self._sightings_factory)]}
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
    """
    Allowed sighting key: ['hashes', 'md5', 'sha1', 'sha256', 'sha512']
    """
    hashes: Hashes
    external_analysis_link: List[str] = None
    filesize: int = None
    filetype: str = None
    file_url: str = None
    mimetype: str = None
    filename: str = None
    filepath: str = None

    def _get_sightings_allowed_keys(self):
        return ['hashes', 'md5', 'sha1', 'sha256', 'sha512']

    def _get_sightings_prefix(self):
        return 'file'

@dataclass
class AndroidApp:
    package_name: str
    app_name: str = None
    developer: str = None
    version_name: str = None
    permissions: str = None


@dataclass
class ApkAtom(Atom):
    """
    Allowed sighting key: ['android', 'package_name', 'version_name', 'hashes', 'md5', 'sha1', 'sha256', 'sha512']
    """
    android: AndroidApp
    hashes: Hashes
    external_analysis_link: List[str] = None
    filesize: int = None
    filetype: str = None
    file_url: str = None
    mimetype: str = None
    filename: str = None
    filepath: str = None

    def _get_sightings_allowed_keys(self):
        return ['android', 'package_name', 'version_name', 'hashes', 'md5', 'sha1', 'sha256', 'sha512']

    def _get_sightings_prefix(self):
        return 'apk'

@dataclass
class AsAtom(Atom):
    """
    Allowed sighting key: ['asn']
    """
    asn: int
    external_analysis_link: List[str] = None
    allocation_date: str = None
    country: str = None
    malware_family: str = None
    owner: str = None
    registry: str = None

    def _get_sightings_allowed_keys(self):
        return ['asn']

    def _get_sightings_prefix(self):
        return 'as'

@dataclass
class CcAtom(Atom):
    """
    Allowed sighting key: ['number']
    number: minLength = 8  maxLength = 19
    """
    number: str
    external_analysis_link: List[str] = None
    bin: int = None
    brand: str = None
    cvx: int = None
    description: str = None
    expiry_date: str = None

    def _get_sightings_allowed_keys(self):
        return ['number']

    def _get_sightings_prefix(self):
        return 'cc'

@dataclass
class CryptoAtom(Atom):
    """
    Allowed sighting key: ['crypto_address', 'crypto_network']
    """
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

    def _get_sightings_allowed_keys(self):
        return ['crypto_address', 'crypto_network']

    def _get_sightings_prefix(self):
        return 'crypto'

@dataclass
class CveAtom(Atom):
    """
    Allowed sighting key: ['cve_id']
    """
    """
    published_at expect the following datetime format: '%Y-%m-%dT%H:%M:%SZ'
    """
    cve_id: str
    cvss: int = None
    cwe: str = None
    external_analysis_link: List[str] = None
    published_at: str = None

    def _get_sightings_allowed_keys(self):
        return ['cve_id']

    def _get_sightings_prefix(self):
        return 'cve'


@dataclass
class Jarm:
    calculated_at: str = None
    fingerprint: str = None
    malicious: bool = None
    malware_family: str = None


@dataclass
class DomainAtom(Atom):
    """
    Allowed sighting key: ['domain']
    """
    domain: str
    external_analysis_link: List[str] = None
    malware_family: str = None
    jarm: Jarm = None

    def _get_sightings_allowed_keys(self):
        return ['domain']

    def _get_sightings_prefix(self):
        return 'domain'

class EmailFlow(Enum):
    TO = 'to'
    FROM = 'from'


@dataclass
class EmailAtom(Atom):
    """
    Allowed sighting key: ['email']
    """
    email: str
    email_flow: EmailFlow = None
    external_analysis_link: List[str] = None

    def _get_sightings_allowed_keys(self):
        return ['email']

    def _get_sightings_prefix(self):
        return 'email'

@dataclass
class FqdnAtom(Atom):
    """
    Allowed sighting key: ['fqdn']
    """
    fqdn: str
    jarm: Jarm = None
    malware_family: str = None
    port: List[int] = None
    ns: List[str] = None
    external_analysis_link: List[str] = None

    def _get_sightings_allowed_keys(self):
        return ['fqdn']

    def _get_sightings_prefix(self):
        return 'fqdn'

@dataclass
class IbanAtom(Atom):
    """
    Allowed sighting key: ['iban']
    """
    iban: str
    holder_name: str = None
    holder_address: str = None
    external_analysis_link: List[str] = None
    bic: str = None
    bank_name: str = None
    bank_address: str = None

    def _get_sightings_allowed_keys(self):
        return ['iban']

    def _get_sightings_prefix(self):
        return 'iban'

@dataclass
class IpService:
    port: int
    service_name: str
    application: str = None
    protocol: str = None


@dataclass
class IpAtom(Atom):
    """
    Allowed sighting key: ['ip_address']
    """
    ip_address: str
    external_analysis_link: List[str] = None
    hostanme: str = None
    ip_version: int = None
    jarm: Jarm = None
    malware_family: str = None
    owner: str = None
    peer_asns: List[int] = None
    services: IpService = None

    def _get_sightings_allowed_keys(self):
        return ['ip_address']

    def _get_sightings_prefix(self):
        return 'ip'


@dataclass
class IpRangeAtom(Atom):
    """
    Allowed sighting key: ['cidr']
    """
    cidr: str
    country: str = None
    allocation_date: str = None
    external_analysis_link: List[str] = None
    owner: str = None
    owner_description: str = None
    registry: str = None

    def _get_sightings_allowed_keys(self):
        return ['cidr']

    def _get_sightings_prefix(self):
        return 'ip_range'

@dataclass
class PasteAtom(Atom):
    """
    Allowed sighting key: ['url']
    """
    url: str
    author: str = None
    title: str = None
    content: str = None
    external_analysis_link: List[str] = None

    def _get_sightings_allowed_keys(self):
        return ['url']

    def _get_sightings_prefix(self):
        return 'paste'

@dataclass
class PhoneNumberAtom(Atom):
    """
    Allowed sighting key: ['international_phone_number', 'national_phone_number']
    """
    """
    country: minLength = 2  maxLength = 2
    """
    company: str = None
    country: str = None
    external_analysis_link: List[str] = None
    international_phone_number: str = None
    national_phone_number: str = None

    def _get_sightings_allowed_keys(self):
        return ['international_phone_number', 'national_phone_number']

    def _get_sightings_prefix(self):
        return 'phone_number'

@dataclass
class RegKeyAtom(Atom):
    """
    Allowed sighting key: ['path']
    """
    path: str
    regkey_value: str = None
    hive: str = None
    external_analysis_link: List[str] = None

    def _get_sightings_allowed_keys(self):
        return ['path']

    def _get_sightings_prefix(self):
        return 'regkey'

@dataclass
class SslAtom(Atom):
    """
    Allowed sighting key: ['hashes', 'md5', 'sha1', 'sha256', 'sha512']
    """
    hashes: Hashes
    issuer: str = None
    public_key: str = None
    serial_number: str = None
    signature: str = None
    signature_algorithm: str = None
    subject: str = None
    valid_not_after: str = None
    valid_not_before: str = None
    external_analysis_link: str = None

    def _get_sightings_allowed_keys(self):
        return ['hashes', 'md5', 'sha1', 'sha256', 'sha512']

    def _get_sightings_prefix(self):
        return 'ssl'


@dataclass
class UrlAtom(Atom):
    """
    Allowed sighting key: ['url']
    """
    url: str
    malware_family: str = None
    jarm: Jarm = None
    http_headers: Dict[str, str] = None
    http_code: int = None
    external_analysis_link: List[str] = None
    reason: str = None

    def _get_sightings_allowed_keys(self):
        return ['url']

    def _get_sightings_prefix(self):
        return 'url'
