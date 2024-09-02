"""
Enums for atom properties
"""

from enum import Enum
from typing import Dict, Union


class AtomType(Enum):
    AS = "as"
    CRYPTO = "crypto"
    DOMAIN = "domain"
    EMAIL = "email"
    FILE = "file"
    IP = "ip"
    IP_RANGE = "ip_range"
    PHONE_NUMBER = "phone_number"
    CERTIFICATE = "certificate"
    URL = "url"


class ThreatType(Enum):
    DDOS = "ddos"
    FRAUD = "fraud"
    HACK = "hack"
    LEAK = "leak"
    MALWARE = "malware"
    PHISHING = "phishing"
    SCAM = "scam"
    SCAN = "scan"
    SPAM = "spam"


ScoreMap = Dict[
    str, Union[int, ThreatType]
]  # Should be replaced by a TypedDict when we drop python 3.7 support
"""
Group a threat type with a score using the following keys:
score -> int (from 0 to 100 included)
threat_type -> ThreatType
"""


class OverrideType(Enum):
    TEMPORARY = "temporary"
    LOCK = "lock"


class SightingType(Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"


class Visibility(Enum):
    PUBLIC = "PUBLIC"
    ORGANIZATION = "ORGANIZATION"


class SightingRelation(Enum):
    SIGHTING = "sighting"
    DNS = "dns"
