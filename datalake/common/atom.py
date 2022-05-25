"""
Enums for atom properties
"""
from enum import Enum
from typing import Dict, Union


class AtomType(Enum):
    APK = 'apk'
    AS = 'as'
    CC = 'cc'
    CRYPTO = 'crypto'
    CVE = 'cve'
    DOMAIN = 'domain'
    EMAIL = 'email'
    FILE = 'file'
    FQDN = 'fqdn'
    IBAN = 'iban'
    IP = 'ip'
    IP_RANGE = 'ip_range'
    PASTE = 'paste'
    PHONE_NUMBER = 'phone_number'
    REGKEY = 'regkey'
    SSL = 'ssl'
    URL = 'url'


class ThreatType(Enum):
    DDOS = 'ddos'
    FRAUD = 'fraud'
    HACK = 'hack'
    LEAK = 'leak'
    MALWARE = 'malware'
    PHISHING = 'phishing'
    SCAM = 'scam'
    SCAN = 'scan'
    SPAM = 'spam'


ScoreMap = Dict[str, Union[int, ThreatType]]  # Should be replaced by a TypedDict when we drop python 3.7 support
"""
Group a threat type with a score using the following keys:
score -> int (from 0 to 100 included)
threat_type -> ThreatType
"""


class OverrideType(Enum):
    PERMANENT = 'permanent'
    TEMPORARY = 'temporary'
    LOCK = 'lock'


class SightingType(Enum):
    POSITIVE = 'POSITIVE'
    NEGATIVE = 'NEGATIVE'
    NEUTRAL = 'NEUTRAL'


class Visibility(Enum):
    PUBLIC = 'PUBLIC'
    ORGANIZATION = 'ORGANIZATION'
