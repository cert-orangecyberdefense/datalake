import pytest
import responses
import json
from datalake import Datalake
from tests.common.fixture import datalake

mock_results_data = [
    {
        "aliases": None,
        "category_id": 6,
        "category_name": "Vulnerability",
        "created_at": "2023-10-18T00:10:27.957064+00:00",
        "custom_fields": None,
        "description": "CVSS Score: 3.1 -- CVE numbers: CVE-2004-2770, CVE-2011-3389",
        "external_references": [
            {
                "description": "Vulnerability Intelligence Watch bulletin from OCD",
                "source_name": "Orange Cyberdefense",
                "url": "https://portal.cert.orangecyberdefense.com/vulns/15832",
            },
            {"url": "http://download.novell.com/Download?buildid=5xXFez1MfCE"},
            {"url": "http://download.novell.com/Download?buildid=LRE6jKDRyL0~"},
            {"url": "http://download.novell.com/Download?buildid=aHusLf7UH54"},
            {"url": "http://download.novell.com/Download?buildid=fRhKUupU1Zk"},
            {"url": "http://download.novell.com/Download?buildid=wyCZONZwAi4~"},
            {
                "url": "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?lang=en&cc=us&objectID=c03839862"
            },
            {
                "url": "http://lists.apple.com/archives/security-announce/2014/Feb/msg00000.html"
            },
            {
                "url": "http://lists.fedoraproject.org/pipermail/package-announce/2014-November/142795.html"
            },
            {"url": "http://lists.opensuse.org/opensuse-updates/2020-01/msg00088.html"},
            {
                "url": "http://lists.suse.com/pipermail/sle-security-updates/2020-January/006354.html"
            },
            {"url": "http://support.apple.com/kb/HT6011"},
            {
                "url": "http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html"
            },
            {
                "url": "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html"
            },
            {
                "url": "https://campus.barracuda.com/product/emailsecuritygateway/doc/11141920/release-notes"
            },
            {
                "url": "https://lists.debian.org/debian-lts-announce/2015/02/msg00008.html"
            },
            {
                "url": "https://lists.debian.org/debian-lts-announce/2016/01/msg00025.html"
            },
            {"url": "https://security-tracker.debian.org/tracker/CVE-2011-3389"},
            {
                "url": "https://securitydocs.business.xerox.com/wp-content/uploads/2017/09/cert_Security_Mini-_Bulletin_XRX17Z_for_WC75xx_v1.0-1.pdf"
            },
            {"url": "https://www.ibm.com/support/pages/node/6322533"},
        ],
        "id": 23799,
        "name": "[15832] TLS Predictable Initialization Vector CBC Mode Vulnerability",
        "stix_uuid": "vulnerability--2fda284e-168b-46ae-b5a5-383b005ca22c",
        "tags": ["cve-2004-2770", "cve-2011-3389"],
        "update_mode": "FORCE",
        "updated_at": "2023-10-18T00:10:27.957073+00:00",
    }
]


def mock_api_response():
    responses.add(
        responses.POST,
        "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/tag-subcategory/filtered/",
        json={"results": mock_results_data},  # Only return the "results" part
        status=200,
    )


@responses.activate
def test_get_filtered_and_sorted_list(datalake: Datalake):
    mock_api_response()
    params = {
        "category_name": "Vulnerability",
        "limit": 5,
        "offset": 0,
    }
    filtered_subcategory = datalake.FilteredTagSubcategory
    response = filtered_subcategory.get_filtered_and_sorted_list(**params)
    # Verify the response contains the "results" part
    assert "results" in response
    assert response["results"] == mock_results_data
    # Verify the structure and content of the "results" part
    assert isinstance(response["results"], list), "Results should be a list"
    assert responses.calls[
        0
    ].request.url, "https://datalake.cert.orangecyberdefense.com/api/v2/mrti/tag-subcategory/filtered/"
    assert responses.calls[0].request.method, "POST"
    request_body = json.loads(responses.calls[0].request.body)
    assert request_body["category_name"], params["category_name"]
    assert request_body["limit"], params["limit"]

    for result in response["results"]:
        assert "category_id" in result, "Result should have a category_id"
        assert isinstance(
            result["category_id"], int
        ), "category_id should be an integer"
        assert "category_name" in result, "Result should have a category_name"
        assert isinstance(
            result["category_name"], str
        ), "category_name should be a string"
        assert "created_at" in result, "Result should have a created_at"
        assert isinstance(result["created_at"], str), "created_at should be a string"
        assert "description" in result, "Result should have a description"
        assert isinstance(result["description"], str), "description should be a string"
        assert "external_references" in result, "Result should have external_references"
        assert isinstance(
            result["external_references"], list
        ), "external_references should be a list"
        assert "id" in result, "Result should have an id"
        assert isinstance(result["id"], int), "id should be an integer"
        assert "name" in result, "Result should have a name"
        assert isinstance(result["name"], str), "name should be a string"
        assert "stix_uuid" in result, "Result should have a stix_uuid"
        assert isinstance(result["stix_uuid"], str), "stix_uuid should be a string"
        assert "tags" in result, "Result should have tags"
        assert isinstance(result["tags"], list), "tags should be a list"
        assert all(
            isinstance(tag, str) for tag in result["tags"]
        ), "All tags should be strings"
        assert "update_mode" in result, "Result should have an update_mode"
        assert isinstance(result["update_mode"], str), "update_mode should be a string"
        assert "updated_at" in result, "Result should have an updated_at"
        assert isinstance(result["updated_at"], str), "updated_at should be a string"

        # Test the structure of nested objects like 'external_references'
        for ref in result["external_references"]:
            assert "url" in ref, "Each external reference should have a url"
            assert isinstance(
                ref["url"], str
            ), "The url in external references should be a string"
            # Test optional fields with get to avoid KeyError if the field is not present
            if "description" in ref:
                assert isinstance(
                    ref["description"], str
                ), "The description in external references should be a string"
            if "source_name" in ref:
                assert isinstance(
                    ref["source_name"], str
                ), "The source_name in external references should be a string"
