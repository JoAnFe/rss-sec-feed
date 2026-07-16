import unittest

import server


SOURCE = {"id": "src", "name": "Source", "category": "cyber", "preferred": False}


def item(title, cves=None, summary=""):
    return {"id": "i", "title": title, "link": "https://example.com/i",
            "ts": 1_000_000.0, "guessed": False, "summary": summary,
            "topics": [], "cves": cves or []}


class KevParsingTests(unittest.TestCase):
    def test_ransomware_flag_and_fields(self):
        payload = {"vulnerabilities": [
            {"cveID": "CVE-2026-1", "knownRansomwareCampaignUse": "Known",
             "dueDate": "2026-08-01", "dateAdded": "2026-07-01",
             "vendorProject": "Ivanti", "product": "Connect Secure",
             "vulnerabilityName": "Auth bypass"},
            {"cveID": "cve-2026-2", "knownRansomwareCampaignUse": "Unknown",
             "vendorProject": "Acme", "product": "Widget"},
            {"knownRansomwareCampaignUse": "Known"},  # no cveID -> skipped
        ]}
        records = server._kev_records_from_payload(payload)

        self.assertEqual(set(records), {"CVE-2026-1", "CVE-2026-2"})  # id upper-cased
        self.assertTrue(records["CVE-2026-1"]["ransomware"])
        self.assertFalse(records["CVE-2026-2"]["ransomware"])
        self.assertEqual(records["CVE-2026-1"]["due_date"], "2026-08-01")
        self.assertEqual(records["CVE-2026-1"]["product"], "Connect Secure")


class EpssParsingTests(unittest.TestCase):
    def test_parses_floats_and_skips_bad_rows(self):
        rows = [
            {"cve": "CVE-2026-1", "epss": "0.94210", "percentile": "0.995"},
            {"cve": "CVE-2026-2", "epss": "not-a-number", "percentile": "0.5"},
            {"epss": "0.3", "percentile": "0.4"},  # no cve -> skipped
        ]
        scores = server._epss_scores_from_rows(rows)

        self.assertEqual(set(scores), {"CVE-2026-1"})
        self.assertAlmostEqual(scores["CVE-2026-1"]["epss"], 0.9421)
        self.assertAlmostEqual(scores["CVE-2026-1"]["percentile"], 0.995)


class ItemIntelTests(unittest.TestCase):
    def setUp(self):
        self._kev = dict(server.KEV)
        self._epss = dict(server.EPSS)
        records = {
            "CVE-2026-1": {"ransomware": True, "due_date": "2026-08-01",
                           "vendor": "Ivanti", "product": "Connect Secure"},
            "CVE-2026-2": {"ransomware": False, "due_date": "2026-09-01",
                           "vendor": "Acme", "product": "Widget"},
        }
        server.KEV.update(cves=set(records), records=records)
        server.EPSS.update(scores={
            "CVE-2026-1": {"epss": 0.94, "percentile": 0.99},
            "CVE-2026-2": {"epss": 0.02, "percentile": 0.30},
        })

    def tearDown(self):
        server.KEV.clear(); server.KEV.update(self._kev)
        server.EPSS.clear(); server.EPSS.update(self._epss)

    def test_reduces_to_most_severe_signal_across_cves(self):
        intel = server.item_intel(item("Two flaws", cves=["CVE-2026-2", "CVE-2026-1"]))

        self.assertTrue(intel["kev"])
        self.assertTrue(intel["ransomware"])            # any member ransomware
        self.assertEqual(intel["kev_due"], "2026-08-01")  # earliest deadline
        self.assertEqual(intel["epss"], 0.94)           # highest probability
        self.assertTrue(intel["epss_high"])

    def test_non_ransomware_kev_item(self):
        intel = server.item_intel(item("One flaw", cves=["CVE-2026-2"]))
        self.assertTrue(intel["kev"])
        self.assertFalse(intel["ransomware"])
        self.assertFalse(intel["epss_high"])

    def test_no_intel_without_matching_cves(self):
        self.assertEqual(server.item_intel(item("General news")), {})
        self.assertEqual(server.item_intel(item("Unknown", cves=["CVE-2000-9"])), {})

    def test_actionability_boosts_ransomware_and_epss(self):
        # Pass an empty KEV id set to isolate the intel bonuses from the +60
        # KEV-topic score, keeping the total below the 100 cap so the exact
        # contribution is observable (item_intel still reads the records/scores).
        rw = item("Acme software flaw", cves=["CVE-2026-1"])
        plain = item("Acme software flaw", cves=["CVE-2026-2"])

        rw_action = server.actionability_details(rw, SOURCE, set())
        plain_action = server.actionability_details(plain, SOURCE, set())

        self.assertIn("Ransomware campaign", rw_action["reasons"])
        self.assertTrue(any(r.startswith("High EPSS") for r in rw_action["reasons"]))
        self.assertEqual(
            rw_action["score"] - plain_action["score"],
            server.RANSOMWARE_ACTION_BONUS + server.EPSS_ACTION_BONUS)

    def test_kev_ransomware_item_is_critical(self):
        action = server.actionability_details(
            item("Ivanti flaw", cves=["CVE-2026-1"]), SOURCE, server.KEV["cves"])
        self.assertEqual(action["level"], "critical")
        self.assertIn("CISA KEV", action["reasons"])
        self.assertIn("Ransomware campaign", action["reasons"])

    def test_payload_includes_intel_block(self):
        payload = server.item_payload(
            item("Ivanti flaw", cves=["CVE-2026-1"]), SOURCE, server.KEV["cves"])
        self.assertIn("intel", payload)
        self.assertTrue(payload["intel"]["ransomware"])
        self.assertEqual(payload["intel"]["kev_product"], "Ivanti Connect Secure")


if __name__ == "__main__":
    unittest.main()
