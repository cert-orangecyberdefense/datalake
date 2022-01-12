"""
Enums for atom properties
"""
from enum import Enum


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


class OverrideType(Enum):
    PERMANENT = 'permanent'
    TEMPORARY = 'temporary'
    LOCK = 'lock'
