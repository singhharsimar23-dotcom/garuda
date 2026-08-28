import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import unittest
import urllib.parse

from fastapi.testclient import TestClient
import requests
from requests.adapters import HTTPAdapter
from requests.models import Response as RequestsResponse
import stix2
from taxii2client.v21 import ApiRoot, Collection, Server

from garuda.api.main import app
from garuda.database import (
    _IN_MEMORY_STIX_OBJECTS,
    get_taxii_collections,
    insert_stix_objects,
    register_taxii_subscriber,
)
from garuda.detection.ioc_confidence import compute_ioc_confidence
from garuda.response.stix_export import create_stix_bundle, persist_stix_bundle
from lib.ioc_confidence import compute_ioc_confidence as lib_compute_ioc_confidence


class FastAPITestAdapter(HTTPAdapter):
    """
    Adapter enabling the official OASIS taxii2client (built on requests)
    to communicate directly and synchronously with FastAPI TestClient.
    """

    def __init__(self, client: TestClient):
        super().__init__()
        self.client = client

    def send(self, request, **kwargs):
        parsed = urllib.parse.urlparse(request.url)
        path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"

        headers = dict(request.headers)
        resp = self.client.request(
            method=request.method,
            url=path,
            headers=headers,
            content=request.body,
        )

        r = RequestsResponse()
        r.status_code = resp.status_code
        r.headers.update(resp.headers)
        r._content = resp.content
        r.url = request.url
        r.request = request
        return r


class TestTaxii2ServerAndSTIX21(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_client = TestClient(app)
        cls.adapter = FastAPITestAdapter(cls.test_client)

        # Register test subscribers
        asyncio.run(
            register_taxii_subscriber(
                name="AFCERT Primary Node",
                api_key="afcert-secret-key-1234567890abcdef",
                allowed_collections=["*"],
            )
        )
        asyncio.run(
            register_taxii_subscriber(
                name="DRDO Restricted Node",
                api_key="drdo-secret-key-1234567890abcdef",
                allowed_collections=["drdo-defence"],
            )
        )

    def _create_oasis_server(self, api_key: str = "afcert-secret-key-1234567890abcdef") -> Server:
        """Create and configure an official OASIS TAXII 2.1 Server instance with adapter."""
        server = Server("http://taxii.garuda.internal/taxii2/", user=api_key, password="")
        server._conn.session.mount("http://", self.adapter)
        server._conn.session.mount("https://", self.adapter)
        return server

    def setUp(self):
        # Seed test STIX objects before each test
        self.test_alert_nic = {
            "id": "alert-nic-001",
            "domain": "gov-portal-update.in",
            "hosting_ip": "185.220.101.5",
            "sector": "NIC",
            "score": 88,
            "cluster_id": "APT36-CAMPAIGN-01",
            "geopolitical_ref": "IN-PK-CYBER-OBS-2026",
            "analyst_note": "Targeted phishing campaign impersonating NIC SSO login portal.",
            "signals": {
                "keyword_score": 20,
                "keyword_tier": "tier1",
                "nic_similarity": 0.92,
                "nic_match": "gov.in",
                "homoglyph": True,
                "domain_age_days": 4,
                "asn_match": True,
                "c2_ports": [443, 8443],
                "otx_attributed": True,
                "tension_index": 0.75,
            },
        }

        self.test_alert_drdo = {
            "id": "alert-drdo-002",
            "domain": "drdo-missile-portal.space",
            "hosting_ip": "194.36.191.12",
            "sector": "DRDO",
            "score": 95,
            "cluster_id": "APT36-CAMPAIGN-02",
            "geopolitical_ref": "IN-PK-CYBER-OBS-2026",
            "analyst_note": "Spearphishing targeting DRDO defence research laboratories.",
            "signals": {
                "keyword_score": 25,
                "keyword_tier": "tier1",
                "nic_similarity": 0.70,
                "domain_age_days": 2,
                "asn_match": True,
                "c2_ports": [443],
                "otx_attributed": True,
                "tension_index": 0.85,
            },
        }

        asyncio.run(persist_stix_bundle(self.test_alert_nic))
        asyncio.run(persist_stix_bundle(self.test_alert_drdo))

    def test_ioc_confidence_calculation_and_zero_hardcoding(self):
        """
        Acceptance Test: Every row's confidence traces to a lib/ioc_confidence call;
        no hardcoded numbers in STIX object creation.
        """
        # Use the SAME signals as test_alert_nic to ensure equality holds
        nic_signals = self.test_alert_nic["signals"]
        conf, method = compute_ioc_confidence(nic_signals)
        lib_conf, lib_method = lib_compute_ioc_confidence(nic_signals)

        # Both paths must agree
        self.assertEqual(conf, lib_conf)
        self.assertEqual(method, lib_method)
        self.assertGreaterEqual(conf, 70)
        self.assertIn("NIC High-Similarity", method)
        self.assertIn("Unicode Homoglyph", method)
        self.assertIn("Known Threat Infrastructure", method)

        # Verify the arbitrary-signals helper also works for provenance checking
        arb_signals = {
            "nic_similarity": 0.90,
            "homoglyph": True,
            "keyword_score": 20,
            "domain_age_days": 5,
            "asn_match": True,
            "c2_ports": [8443],
            "otx_attributed": True,
            "tension_index": 0.80,
        }
        arb_conf, arb_method = compute_ioc_confidence(arb_signals)
        self.assertGreaterEqual(arb_conf, 70)
        self.assertIn("GARUDA Multi-Signal Engine", arb_method)

        # Ensure create_stix_bundle populates indicator with computed confidence
        bundle = create_stix_bundle(self.test_alert_nic)
        indicator = next(o for o in bundle.objects if o.type == "indicator")
        self.assertEqual(indicator.confidence, conf)
        self.assertEqual(indicator.get("x_garuda_confidence_methodology"), method)

    def test_stix_objects_deserialize_cleanly_via_stix2_parse(self):
        """
        Acceptance Test: Every row in stix_objects deserializes cleanly via stix2.parse().
        """
        self.assertGreater(len(_IN_MEMORY_STIX_OBJECTS), 0)
        for row in _IN_MEMORY_STIX_OBJECTS:
            raw_dict = row.get("raw")
            self.assertIsNotNone(raw_dict)
            raw_json = json.dumps(raw_dict)
            parsed_obj = stix2.parse(raw_json, allow_custom=True)
            self.assertIsNotNone(parsed_obj)
            self.assertEqual(str(parsed_obj.id), row["id"])
            self.assertEqual(str(parsed_obj.type), row["type"])

            if row["type"] == "indicator":
                # Verify custom properties
                self.assertIsNotNone(parsed_obj.get("x_garuda_target_sector"))
                self.assertIsNotNone(parsed_obj.get("x_garuda_confidence_methodology"))

    def test_official_oasis_taxii2_client_discovery_and_collections(self):
        """
        Acceptance Test: Official OASIS taxii2-client discovers server,
        inspects API root, and lists collections.
        """
        server = self._create_oasis_server()

        self.assertIn("GARUDA", server.title)
        self.assertGreater(len(server.api_roots), 0)

        # Inspect default API root
        api_root = server.default or server.api_roots[0]
        api_root._conn.session.mount("http://", self.adapter)
        api_root._conn.session.mount("https://", self.adapter)

        self.assertIn("application/taxii+json;version=2.1", api_root.versions)
        self.assertEqual(api_root.max_content_length, 10485760)

        # Refresh and list collections
        api_root.refresh_collections()
        colls = api_root.collections
        self.assertGreaterEqual(len(colls), 5)

        slugs = [c.alias for c in colls if hasattr(c, "alias")]
        self.assertTrue(any("high-confidence" in str(s) for s in slugs) or any("high-confidence" in c.title.lower() for c in colls))
        self.assertTrue(any("nic-sector" in str(s) for s in slugs) or any("nic" in c.title.lower() for c in colls))

    def test_official_oasis_taxii2_client_pull_objects_and_added_after(self):
        """
        Acceptance Test: Pull objects from a collection using taxii2-client
        and verify added_after time filtering.
        """
        server = self._create_oasis_server()
        api_root = server.api_roots[0]
        api_root._conn.session.mount("http://", self.adapter)
        api_root._conn.session.mount("https://", self.adapter)

        api_root.refresh_collections()

        # Find high-confidence collection
        high_conf_coll = None
        for c in api_root.collections:
            c._conn.session.mount("http://", self.adapter)
            c._conn.session.mount("https://", self.adapter)
            if c.alias == "high-confidence" or "high-confidence" in str(c.id).lower() or "high confidence" in c.title.lower():
                high_conf_coll = c
                break

        self.assertIsNotNone(high_conf_coll, "high-confidence collection must exist")

        # Fetch objects
        objects_envelope = high_conf_coll.get_objects()
        self.assertIn("objects", objects_envelope)
        objects = objects_envelope["objects"]
        self.assertGreater(len(objects), 0)

        # Validate STIX objects in envelope
        types = [o["type"] for o in objects]
        self.assertIn("indicator", types)
        self.assertIn("domain-name", types)

        # Test added_after filter: past timestamp should include objects
        past_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        filtered_past = high_conf_coll.get_objects(added_after=past_ts)
        self.assertGreater(len(filtered_past["objects"]), 0)

        # Test added_after filter: future timestamp should yield 0 objects
        future_ts = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        filtered_future = high_conf_coll.get_objects(added_after=future_ts)
        self.assertEqual(len(filtered_future["objects"]), 0)

    def test_taxii_manifest_and_single_object_endpoints(self):
        """
        Verify /manifest/ and /objects/{object_id}/ endpoints.
        Uses 'all-iocs' collection which always receives both seeded alerts.
        """
        collections = asyncio.run(get_taxii_collections())
        # all-iocs is always populated from both seeded alerts
        target_coll = next(c for c in collections if c["slug"] == "all-iocs")
        coll_id = str(target_coll["id"])

        # Verify the collection has objects via the objects endpoint first
        res_objects = self.test_client.get(
            f"/taxii2/api_v1/collections/{coll_id}/objects/",
            headers={"Authorization": "Bearer afcert-secret-key-1234567890abcdef"},
        )
        self.assertEqual(res_objects.status_code, 200)
        objects_data = res_objects.json()
        self.assertGreater(len(objects_data["objects"]), 0, "all-iocs collection must contain seeded objects")
        first_obj_id = objects_data["objects"][0]["id"]

        # Test Manifest
        res_manifest = self.test_client.get(
            f"/taxii2/api_v1/collections/{coll_id}/manifest/",
            headers={"Authorization": "Bearer afcert-secret-key-1234567890abcdef"},
        )
        self.assertEqual(res_manifest.status_code, 200)
        self.assertEqual(res_manifest.headers["Content-Type"], "application/taxii+json;version=2.1")
        manifest_data = res_manifest.json()
        self.assertIn("objects", manifest_data)
        self.assertGreater(len(manifest_data["objects"]), 0)
        manifest_ids = [m["id"] for m in manifest_data["objects"]]

        # Test Single Object Lookup — use first known object
        res_single = self.test_client.get(
            f"/taxii2/api_v1/collections/{coll_id}/objects/{first_obj_id}/",
            headers={"Authorization": "Bearer afcert-secret-key-1234567890abcdef"},
        )
        self.assertEqual(res_single.status_code, 200)
        self.assertEqual(res_single.headers["Content-Type"], "application/taxii+json;version=2.1")
        single_data = res_single.json()
        self.assertEqual(single_data["objects"][0]["id"], first_obj_id)

    def test_taxii_auth_rejection_with_proper_taxii_error_schema(self):
        """
        Acceptance Test: Auth rejects unrecognized API key with a proper TAXII 2.1
        error response with application/taxii+json;version=2.1 (not bare 401 HTML).
        """
        collections = asyncio.run(get_taxii_collections())
        coll_id = str(collections[0]["id"])

        # Request with completely invalid API key
        res = self.test_client.get(
            f"/taxii2/api_v1/collections/{coll_id}/objects/",
            headers={"Authorization": "Bearer completely-bogus-api-key-999"},
        )
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.headers["Content-Type"], "application/taxii+json;version=2.1")

        err_body = res.json()
        self.assertEqual(err_body.get("title"), "Unauthorized")
        self.assertEqual(err_body.get("http_status"), "401")
        self.assertIn("TAXII-AUTH-401", err_body.get("error_id", ""))

        # Request with subscriber not authorized for target collection
        res_restricted = self.test_client.get(
            f"/taxii2/api_v1/collections/{coll_id}/objects/",
            headers={"Authorization": "Bearer drdo-secret-key-1234567890abcdef"},
        )
        if collections[0]["slug"] != "drdo-defence":
            self.assertEqual(res_restricted.status_code, 401)
            self.assertEqual(res_restricted.headers["Content-Type"], "application/taxii+json;version=2.1")
            self.assertEqual(res_restricted.json()["title"], "Unauthorized")


if __name__ == "__main__":
    unittest.main()
