from unittest.mock import patch
import pytest
import responses
from datetime import datetime, timedelta, timezone

from responses import matchers
import os
import ast


from tests.common.fixture import TestData, datalake  # noqa needed fixture import
from datalake import (
    IpAtom,
    FileAtom,
    EmailAtom,
    UrlAtom,
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
    description_visibility = Visibility.PUBLIC
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
        "description_visibility": "PUBLIC",
        "type": "positive",
        "count": 1,
        "threat_types": ["scam"],
        "editable": False,
    }

    with patch.dict(
        os.environ,
        {
            "IGNORE_SIGHTING_BUILDER_WARNING": "1",
        },
        clear=True,
    ):
        payload = datalake.Sightings._prepare_sightings_payload(
            atoms,
            None,
            start,
            end,
            sighting_type,
            description_visibility,
            count,
            payload_threat_types,
            editable=False,
        )

    assert expected_payload == payload


def test_submit_sightings_without_editable(datalake):
    atoms = [file_atom, ip_atom, ip_atom1]
    sighting_type = SightingType.POSITIVE
    description_visibility = Visibility.PUBLIC
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
        "description_visibility": "PUBLIC",
        "type": "positive",
        "count": 1,
        "threat_types": ["scam"],
    }

    with patch.dict(
        os.environ,
        {
            "IGNORE_SIGHTING_BUILDER_WARNING": "1",
        },
        clear=True,
    ):
        payload = datalake.Sightings._prepare_sightings_payload(
            atoms,
            None,
            start,
            end,
            sighting_type,
            description_visibility,
            count,
            payload_threat_types,
        )

    assert expected_payload == payload


def test_prepare_sightings_payload_with_empty_tags(datalake):
    atoms = [file_atom]
    sighting_type = SightingType.NEUTRAL
    description_visibility = Visibility.ORGANIZATION
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
        "description_visibility": "ORGANIZATION",
        "type": "neutral",
        "count": 1,
    }

    with patch.dict(
        os.environ,
        {
            "IGNORE_SIGHTING_BUILDER_WARNING": "1",
        },
        clear=True,
    ):
        payload = datalake.Sightings._prepare_sightings_payload(
            atoms,
            None,
            start,
            end,
            sighting_type,
            description_visibility,
            count,
            tags=[],
        )

    assert expected_payload == payload


def test_prepare_sightings_payload_with_impersonate_id(datalake):
    atoms = [file_atom]
    sighting_type = SightingType.NEUTRAL
    description_visibility = Visibility.ORGANIZATION
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
        "description_visibility": "ORGANIZATION",
        "type": "neutral",
        "count": 1,
        "impersonate_id": "1234567890",
    }

    with patch.dict(
        os.environ,
        {
            "IGNORE_SIGHTING_BUILDER_WARNING": "1",
        },
        clear=True,
    ):
        payload = datalake.Sightings._prepare_sightings_payload(
            atoms,
            None,
            start,
            end,
            sighting_type,
            description_visibility,
            count,
            impersonate_id=impersonate_id,
        )

    assert expected_payload == payload


@responses.activate
def test_submit_sightings(datalake):
    url = (
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-sighting"]
    )

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
        "description_visibility": "PUBLIC",
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
            "source_uses": ["commercial", "internal", "notify", "sensitive"],
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

    with patch.dict(
        os.environ,
        {
            "IGNORE_SIGHTING_BUILDER_WARNING": "1",
        },
        clear=True,
    ):
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
        == '"sighting_type" has to be an instance of the SightingType class.'
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
        " has to be an instance of the ThreatType class."
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
    assert (
        str(err.value) == """For NEUTRAL sightings, "threat_types" can't be passed."""
    )


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
    assert (
        str(err.value)
        == '"description_visibility" has to be an instance of the Visibility class.'
    )


def test_submit_sightings_bad_atom(datalake):
    with pytest.raises(TypeError) as err:
        with patch.dict(
            os.environ,
            {
                "IGNORE_SIGHTING_BUILDER_WARNING": "1",
            },
            clear=True,
        ):
            datalake.Sightings.submit_sighting(
                start,
                end,
                SightingType.POSITIVE,
                Visibility.PUBLIC,
                1,
                threat_types,
                atoms=[ip_atom, ip_atom1, file_atom, "not_an_atom"],
            )
    assert str(err.value) == '"atoms" needs to be a list of Atom subclasses.'


@responses.activate
def test_bulk_submit_sightings_success(datalake):
    url = (
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-bulk-sighting"]
    )

    f1 = FileAtom(
        hashes=Hashes(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
    )
    ip1 = IpAtom("52.48.79.33")
    em1 = EmailAtom("hacker@hacker.fr")
    url1 = UrlAtom("http://notfishing.com")

    # You also need to define additional properties for these atoms, shared by all atoms within the same sighting.

    ## Prepare threat types for this sighting
    threat_types = [ThreatType.PHISHING, ThreatType.SCAM]

    ## Prepare start and end timestamps for this sighting
    start = datetime(2025, 12, 16, 10, 0, 0, tzinfo=timezone.utc) - timedelta(hours=1)
    end = datetime(2025, 12, 16, 10, 0, 0, tzinfo=timezone.utc)
    input_sighting = {
        "atoms": [ip1, f1, em1, url1],
        "start_timestamp": start,
        "end_timestamp": end,
        "sighting_type": SightingType.POSITIVE,
        "description_visibility": Visibility.PUBLIC,
        "count": 1,
        "threat_types": threat_types,
        "tags": ["some_tag"],
        "description": "some_description",
        "editable": True,
    }
    expected_request = {
        "data": [
            {
                "count": 1,
                "description": "some_description",
                "description_visibility": "PUBLIC",
                "editable": True,
                "email_list": [{"email": "hacker@hacker.fr"}],
                "end_timestamp": "2025-12-16T10:00:00Z",
                "file_list": [
                    {
                        "hashes": {
                            "md5": "d41d8cd98f00b204e9800998ecf8427e",
                            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        }
                    }
                ],
                "ip_list": [{"ip_address": "52.48.79.33"}],
                "start_timestamp": "2025-12-16T09:00:00Z",
                "tags": ["some_tag"],
                "threat_types": ["phishing", "scam"],
                "type": "positive",
                "url_list": [{"url": "http://notfishing.com"}],
            }
        ]
    }
    expected_res = {
        "count": 1,
        "results": [
            {
                "count": 1,
                "description": "some_description",
                "description_visibility": "PUBLIC",
                "editable": True,
                "end_timestamp": "2025-12-16T10:00:00Z",
                "relation_type": "sighting",
                "reliability": 100,
                "sighting_version": "3.0.0",
                "sightings": {
                    "email_list": [{"email": "hacker@hacker.fr"}],
                    "file_list": [
                        {
                            "hashes": {
                                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                            }
                        }
                    ],
                    "ip_list": [{"ip_address": "52.48.79.33"}],
                    "url_list": [{"url": "http://notfishing.com"}],
                },
                "source_context": {
                    "source_id": "org: Orange Cyberdefense",
                    "source_uses": ["sightings"],
                },
                "start_timestamp": "2025-12-16T09:00:00Z",
                "tags": [{"categories": [], "name": "some_tag"}],
                "threat_types": ["phishing", "scam"],
                "timestamp_created": "2025-12-16T10:00:00Z",
                "type": "positive",
                "uid": "e14dd426-ed41-436c-9e0e-0d785e750428",
            }
        ],
    }

    responses.post(
        url=url,
        json=expected_res,
        status=200,
        match=[matchers.json_params_matcher(expected_request)],
    )

    with patch.dict(
        os.environ,
        {
            "IGNORE_SIGHTING_BUILDER_WARNING": "1",
        },
        clear=True,
    ):
        res = datalake.Sightings.bulk_submit_sightings(sightings=[input_sighting])

    assert res == expected_res


def test_bulk_submit_sightings_payload_error(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.bulk_submit_sightings(
            sightings=[
                {
                    "atoms": [FileAtom(Hashes(md5="d41d8cd98f00b204e9800998ecf8427e"))],
                    "start_timestamp": start,
                    "end_timestamp": end,
                    "sighting_type": SightingType.NEUTRAL,
                    "description_visibility": Visibility.PUBLIC,
                    "count": 3,
                    "threat_types": threat_types,
                    "tags": ["some_tag_bis"],
                    "description": "some_description_bis",
                    "editable": False,
                }
            ]
        )
    assert (
        str(err.value) == """For NEUTRAL sightings, "threat_types" can't be passed."""
    )


@responses.activate
def test_bulk_submit_sightings_failure(datalake):
    url = (
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-bulk-sighting"]
    )

    hashkeys = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "a7b25b324871a7695aa2cc5d09681dda",
        "1ed07771327e850255b09b042ad00e3d",
        "bf1f33c3a56e1dfda6a2f4f3d3e4361a",
    ]

    # You also need to define additional properties for these atoms, shared by all atoms within the same sighting.

    ## Prepare threat types for this sighting
    threat_types = [ThreatType.PHISHING, ThreatType.SCAM]

    ## Prepare start and end timestamps for this sighting
    start = datetime(2025, 12, 16, 10, 0, 0, tzinfo=timezone.utc) - timedelta(hours=1)
    end = datetime(2025, 12, 16, 10, 0, 0, tzinfo=timezone.utc)
    input_sighting = {
        "hashkeys": hashkeys,
        "start_timestamp": start,
        "end_timestamp": end,
        "sighting_type": SightingType.POSITIVE,
        "description_visibility": Visibility.PUBLIC,
        "count": 1,
        "threat_types": threat_types,
        "tags": ["some_tag"],
        "description": "some_description",
        "editable": True,
    }
    expected_request = {
        "data": [
            {
                "count": 1,
                "description": "some_description",
                "description_visibility": "PUBLIC",
                "editable": True,
                "end_timestamp": "2025-12-16T10:00:00Z",
                "hashkeys": hashkeys,
                "start_timestamp": "2025-12-16T09:00:00Z",
                "tags": ["some_tag"],
                "threat_types": ["phishing", "scam"],
                "type": "positive",
            }
        ]
    }
    expected_res = {
        "data": {
            "0": {
                "hashkeys": [
                    "Some of the provided hashkeys has not been found: "
                    "['d41d8cd98f00b204e9800998ecf8427e']"
                ]
            }
        }
    }

    responses.post(
        url=url,
        json=expected_res,
        status=422,
        match=[matchers.json_params_matcher(expected_request)],
    )

    with patch.dict(
        os.environ,
        {
            "IGNORE_SIGHTING_BUILDER_WARNING": "1",
        },
        clear=True,
    ):
        with pytest.raises(ValueError) as exc:
            datalake.Sightings.bulk_submit_sightings(sightings=[input_sighting])

    prefix = "422 HTTP code: "
    msg = str(exc.value)
    assert msg.startswith(prefix)

    payload = ast.literal_eval(msg[len(prefix) :])
    assert payload == expected_res


def test_sightings_filtered_bad_ordering(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.sightings_filtered(ordering="bad_ordering")
    assert (
        str(err.value)
        == '"ordering" has to be one of the following: "start_timestamp", "-start_timestamp", "end_timestamp", "-end_timestamp", "timestamp_created", "-timestamp_created", "count", "-count"'
    )


def test_sightings_filtered_bad_type(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.sightings_filtered(sighting_type="bad_sighting_type")
    assert (
        str(err.value)
        == '"sighting_type" has to be an instance of the SightingType class.'
    )


def test_sightings_filtered_bad_visibility(datalake):
    with pytest.raises(ValueError) as err:
        datalake.Sightings.sightings_filtered(description_visibility="bad_visibility")
    assert (
        str(err.value)
        == '"description_visibility" has to be an instance of the Visibility class.'
    )


@responses.activate
def test_sightings_filtered(datalake):
    url = (
        TestData.TEST_CONFIG["main"][TestData.TEST_ENV]
        + TestData.TEST_CONFIG["api_version"]
        + TestData.TEST_CONFIG["endpoints"]["threats-sighting-filtered"]
    )
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
                    "source_uses": ["commercial"],
                },
                "start_timestamp": "2022-12-26T13:00:00Z",
                "tags": [],
                "threat_hashkey": "f39cbce3c4d30d61ccdc99c5fcb3bf6f",
                "threat_types": [],
                "timestamp_created": "2022-12-26T13:41:20Z",
                "type": "neutral",
                "description_visibility": "PUBLIC",
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
