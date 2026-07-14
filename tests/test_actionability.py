import unittest

import server


SOURCE = {"id": "source", "name": "Source", "category": "cyber", "preferred": False}


def item(title, topics=None, cves=None, summary=""):
    return {
        "id": "item", "title": title, "summary": summary,
        "topics": topics or [], "cves": cves or [],
    }


class ActionabilityTests(unittest.TestCase):
    def test_kev_item_is_critical(self):
        value = item("Gateway vulnerability", cves=["CVE-2026-12345"])

        action = server.actionability_details(value, SOURCE, {"CVE-2026-12345"})

        self.assertEqual(action["level"], "critical")
        self.assertIn("CISA KEV", action["reasons"])

    def test_active_exploitation_is_high(self):
        value = item("Attack observed in the wild", topics=["exploited"])

        action = server.actionability_details(value, SOURCE, set())

        self.assertGreaterEqual(action["score"], 45)
        self.assertIn("Active exploitation", action["reasons"])

    def test_critical_impact_is_actionable(self):
        value = item("Critical authentication bypass affects edge appliance")

        action = server.actionability_details(value, SOURCE, set())

        self.assertGreaterEqual(action["score"], server.ACTIONABILITY_THRESHOLD)
        self.assertIn("Critical impact", action["reasons"])

    def test_cve_with_remediation_is_actionable(self):
        value = item("Patch released for gateway flaw", cves=["CVE-2026-12345"])

        action = server.actionability_details(value, SOURCE, set())

        self.assertGreaterEqual(action["score"], server.ACTIONABILITY_THRESHOLD)
        self.assertIn("Remediation available", action["reasons"])

    def test_remediation_signal_alone_is_not_enough(self):
        value = item("Routine software update released")

        action = server.actionability_details(value, SOURCE, set())

        self.assertLess(action["score"], server.ACTIONABILITY_THRESHOLD)

    def test_urgent_containment_is_actionable(self):
        value = item("Urgent: administrators told to shut down exposed servers")

        action = server.actionability_details(value, SOURCE, set())

        self.assertGreaterEqual(action["score"], server.ACTIONABILITY_THRESHOLD)
        self.assertIn("Urgent containment", action["reasons"])

    def test_general_threat_intelligence_is_not_automatically_actionable(self):
        value = item("Quarterly threat landscape review", topics=["threatintel"])

        action = server.actionability_details(value, SOURCE, set())

        self.assertEqual(action["level"], "low")


if __name__ == "__main__":
    unittest.main()
