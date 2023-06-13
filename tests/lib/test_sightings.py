import pytest
import responses
from datetime import datetime

from responses import matchers

from tests.common.fixture import datalake  # noqa needed fixture import
from datalake import (
    IpAtom,
    FileAtom,
    Hashes,
    Jarm,
    IpService,
    SightingType,
    Visibility,
    ThreatType,
)

jarm = Jarm("12/12/2012 12:12:12", "some_fingerprint", True, "some_malware")
ip_service = IpService(77, "some_service", "some_application", "some_protocol")
ip_atom = IpAtom(
    "8.8.8.8",
    ["https://some_url.co"],
    "some_host",
    4,
    jarm,
    "some_malware",
    "owmer",
    [1, 2, 3],
    ip_service,
)
ip_atom1 = IpAtom("9.9.9.9")
hashes = Hashes(
    md5="d26351ba789fba3385d2382aa9d24908",
    sha1="a61e243f25b8b08661011869a53315363697a0f4",
    sha256="c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e",
    sha512="01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944",
)
file_atom = FileAtom(
    hashes=hashes,
    filename="some_filename",
    file_url="some_url",
    external_analysis_link=["some_external_url"],
    filesize=666,
    filetype="jpg",
    mimetype="some_mime",
    filepath="some/path",
)
threat_types = [ThreatType.PHISHING, ThreatType.SCAM]
start = datetime.strptime("2021-05-10T16:20:23Z", "%Y-%m-%dT%H:%M:%SZ")
end = datetime.strptime("2021-05-11T16:20:23Z", "%Y-%m-%dT%H:%M:%SZ")


def test_prepare_sightings_payload(datalake):
    atoms = [file_atom, ip_atom, ip_atom1]
    sighting_type = SightingType.POSITIVE
    visibility = Visibility.PUBLIC
    count = 1
    payload_threat_types = [ThreatType.SCAM]

    expected_payload = {
        "ip_list": [{"ip_address": "8.8.8.8"}, {"ip_address": "9.9.9.9"}],
        "file_list": [
            {
                "hashes": {
                    "md5": "d26351ba789fba3385d2382aa9d24908",
                    "sha1": "a61e243f25b8b08661011869a53315363697a0f4",
                    "sha256": "c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e",
                    "sha512": "01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944",
                }
            }
        ],
        "start_timestamp": "2021-05-10T16:20:23Z",
        "end_timestamp": "2021-05-11T16:20:23Z",
        "visibility": "PUBLIC",
        "type": "positive",
        "count": 1,
        "threat_types": ["scam"],
        "editable": False,
    }

    payload = datalake.Sightings._prepare_sightings_payload(
        atoms,
        None,
        start,
        end,
        sighting_type,
        visibility,
        count,
        payload_threat_types,
        editable=False,
    )

    assert expected_payload == payload


def test_submit_sightings_without_editable(datalake):
    atoms = [file_atom, ip_atom, ip_atom1]
    sighting_type = SightingType.POSITIVE
    visibility = Visibility.PUBLIC
    count = 1
    payload_threat_types = [ThreatType.SCAM]

    expected_payload = {
        "ip_list": [{"ip_address": "8.8.8.8"}, {"ip_address": "9.9.9.9"}],
        "file_list": [
            {
                "hashes": {
                    "md5": "d26351ba789fba3385d2382aa9d24908",
                    "sha1": "a61e243f25b8b08661011869a53315363697a0f4",
                    "sha256": "c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e",
                    "sha512": "01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944",
                }
            }
        ],
        "start_timestamp": "2021-05-10T16:20:23Z",
        "end_timestamp": "2021-05-11T16:20:23Z",
        "visibility": "PUBLIC",
        "type": "positive",
        "count": 1,
        "threat_types": ["scam"],
    }

    payload = datalake.Sightings._prepare_sightings_payload(
        atoms,
        None,
        start,
        end,
        sighting_type,
        visibility,
        count,
        payload_threat_types,
    )

    assert expected_payload == payload


def test_prepare_sightings_payload_with_empty_tags(datalake):
    atoms = [file_atom]
    sighting_type = SightingType.NEUTRAL
    visibility = Visibility.ORGANIZATION
    count = 1

    expected_payload = {
        "file_list": [
            {
                "hashes": {
                    "md5": "d26351ba789fba3385d2382aa9d24908",
                    "sha1": "a61e243f25b8b08661011869a53315363697a0f4",
                    "sha256": "c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e",
                    "sha512": "01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de"
                    "48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944",
                }
            }
        ],
        "start_timestamp": "2021-05-10T16:20:23Z",
        "end_timestamp": "2021-05-11T16:20:23Z",
        "visibility": "ORGANIZATION",
        "type": "neutral",
        "count": 1,
    }

    payload = datalake.Sightings._prepare_sightings_payload(
        atoms, None, start, end, sighting_type, visibility, count, tags=[]
    )

    assert expected_payload == payload


def test_prepare_sightings_payload_with_impersonate_id(datalake):
    atoms = [file_atom]
    sighting_type = SightingType.NEUTRAL
    visibility = Visibility.ORGANIZATION
    count = 1
    impersonate_id = "1234567890"

    expected_payload = {
        "file_list": [
            {
                "hashes": {
                    "md5": "d26351ba789fba3385d2382aa9d24908",
                    "sha1": "a61e243f25b8b08661011869a53315363697a0f4",
                    "sha256": "c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e",
                    "sha512": "01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de"
                    "48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944",
                }
            }
        ],
        "start_timestamp": "2021-05-10T16:20:23Z",
        "end_timestamp": "2021-05-11T16:20:23Z",
        "visibility": "ORGANIZATION",
        "type": "neutral",
        "count": 1,
        "impersonate_id": "1234567890",
    }

    payload = datalake.Sightings._prepare_sightings_payload(
        atoms, None, start, end, sighting_type, visibility, count, impersonate_id=impersonate_id
    )

    assert expected_payload == payload

@responses.activate
def test_submit_sightings(datalake):
    url = "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/sighting/"

    expected_request = {
        "file_list": [
            {
                "hashes": {
                    "md5": "d26351ba789fba3385d2382aa9d24908",
                    "sha1": "a61e243f25b8b08661011869a53315363697a0f4",
                    "sha256": "c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e",
                    "sha512": "01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de"
                    "48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944",
                }
            }
        ],
        "ip_list": [{"ip_address": "8.8.8.8"}, {"ip_address": "9.9.9.9"}],
        "start_timestamp": "2021-05-10T16:20:23Z",
        "end_timestamp": "2021-05-11T16:20:23Z",
        "visibility": "PUBLIC",
        "type": "positive",
        "count": 1,
        "threat_types": ["phishing", "scam"],
        "tags": ["tag1", "tag2"],
        "description": "some description",
    }
    expected_res = {
        "count": 1,
        "end_timestamp": "2021-05-11T16:20:23Z",
        "relation_type": "sighting",
        "reliability": 50,
        "sighting_version": 1,
        "sightings": {
            "file_list": [
                {
                    "hashes": {
                        "md5": "d26351ba789fba3385d2382aa9d24908",
                        "sha1": "a61e243f25b8b08661011869a53315363697a0f4",
                        "sha256": "c056f9206143bc43a7f524f946149ad77c0c491ce816a2865feb6e5f2eaf521e",
                        "sha512": "01525491943d324e928e4d30702fa731db20a2c82dc6b1d8bf7cf157227517de48f10be15053a63be598f75618ea0179c33f8726bde620e976c7ff5a4fbaa944",
                    }
                }
            ],
            "ip_list": [{"ip_address": "8.8.8.8"}, {"ip_address": "9.9.9.9"}],
        },
        "source_context": {
            "source_id": "org:45:public",
            "source_policy": {
                "source_uses": ["commercial", "internal", "notify", "sensitive"]
            },
        },
        "start_timestamp": "2021-05-10T16:20:23Z",
        "tags": [],
        "threat_types": ["phishing", "scam"],
        "timestamp_created": "2022-05-18T12:42:13Z",
        "type": "positive",
        "uid": "1d67a120-8983-4909-a6f0-eec4a7673395",
    }

    responses.post(
        url=url,
        json=expected_res,
        status=200,
        match=[matchers.json_params_matcher(expected_request)],
    )

    res = datalake.Sightings.submit_sighting(
        start,
        end,
        SightingType.POSITIVE,
        Visibility.PUBLIC,
        1,
        threat_types,
        tags=["tag1", "tag2"],
        description="some description",
        atoms=[ip_atom, ip_atom1, file_atom],
    )

    assert res == expected_res


def test_submit_sightings_no_atoms_no_hashkeys(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start, end, SightingType.POSITIVE, Visibility.PUBLIC, 1, threat_types
        )
    assert (
        str(err.value) == "Either threat hashkeys or list of atom objects is required."
    )


def test_submit_sightings_invalid_count(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            Visibility.PUBLIC,
            0,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom],
        )
    assert str(err.value) == "count value minimum: 1"


def test_submit_sightings_bad_sighting_type(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            "positive",
            Visibility.PUBLIC,
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom],
        )
    assert (
        str(err.value)
        == "sighting_type has to be an instance of the SightingType class."
    )


def test_submit_sightings_no_threat_types(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            Visibility.PUBLIC,
            1,
            atoms=[ip_atom, ip_atom1, file_atom],
        )
    assert (
        str(err.value)
        == 'For POSITIVE and NEGATIVE sightings "threat_types" field is required and'
        " has to be an instance of the Visibility class"
    )


def test_submit_sightings_neutral_with_threat_types(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.NEUTRAL,
            Visibility.PUBLIC,
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom],
        )
    assert str(err.value) == "For NEUTRAL sightings, threat_types can't be passed."


def test_submit_sightings_bad_visibility(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            "public",
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom],
        )
    assert str(err.value) == "visibility has to be an instance of the Visibility class."


def test_submit_sightings_bad_atom(datalake):
    with pytest.raises(TypeError) as err:
        datalake.Sightings.submit_sighting(
            start,
            end,
            SightingType.POSITIVE,
            Visibility.PUBLIC,
            1,
            threat_types,
            atoms=[ip_atom, ip_atom1, file_atom, "not_an_atom"],
        )
    assert str(err.value) == "atoms needs to be a list of Atom subclasses."


def test_sightings_filtered_bad_ordering(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.sightings_filtered(ordering="bad_ordering")
    assert (
        str(err.value)
        == 'ordering has to be one of the following: "start_timestamp", "-start_timestamp", "end_timestamp", "-end_timestamp", "timestamp_created", "-timestamp_created", "count", "-count"'
    )


def test_sightings_filtered_bad_type(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.sightings_filtered(sighting_type="bad_sighting_type")
    assert (
        str(err.value)
        == "sighting_type has to be an instance of the SightingType class."
    )


def test_sightings_filtered_bad_visibility(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.sightings_filtered(visibility="bad_visibility")
    assert str(err.value) == "visibility has to be an instance of the Visibility class."


@responses.activate
def test_sightings_filtered(datalake):
    url = "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/threats/sighting/filtered/"
    expected_payload = {"threat_hashkey": "f39cbce3c4d30d61ccdc99c5fcb3bf6f"}
    expected = {
        "count": 1,
        "results": [
            {
                "atom_type": "ip",
                "content": {"ip_content": {"ip_address": "8.8.8.8"}},
                "count": 1,
                "end_timestamp": "2022-12-26T13:00:00Z",
                "is_editable": False,
                "reliability": 50,
                "sighting_file_hashkey": "some_hashkey",
                "sighting_hashkey": "another_hashkey",
                "sighting_version": 1,
                "source_context": {
                    "source_id": "org: org_name",
                    "source_policy": {"source_uses": ["commercial"]},
                },
                "start_timestamp": "2022-12-26T13:00:00Z",
                "tags": [],
                "threat_hashkey": "f39cbce3c4d30d61ccdc99c5fcb3bf6f",
                "threat_types": [],
                "timestamp_created": "2022-12-26T13:41:20Z",
                "type": "neutral",
                "visibility": "PUBLIC",
            }
        ],
    }
    responses.post(
        url=url,
        json=expected,
        status=200,
        match=[matchers.json_params_matcher(expected_payload)],
    )
    res = datalake.Sightings.sightings_filtered("f39cbce3c4d30d61ccdc99c5fcb3bf6f")
    assert res == expected
