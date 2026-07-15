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
        # Actually trips the remediation regex (+20) but, with no CVE/exploit/
        # critical signal, stays below the actionable threshold.
        value = item("Vendor ships a patch for its collaboration tool")

        action = server.actionability_details(value, SOURCE, set())

        self.assertIn("Remediation available", action["reasons"])
        self.assertLess(action["score"], server.ACTIONABILITY_THRESHOLD)

    def test_urgent_containment_is_actionable(self):
        value = item("Urgent: administrators told to shut down exposed servers")

        action = server.actionability_details(value, SOURCE, set())

        self.assertGreaterEqual(action["score"], server.ACTIONABILITY_THRESHOLD)
        self.assertIn("Urgent containment", action["reasons"])

    def test_urgent_colon_headline_scores_containment(self):
        # Regression: the "Urgent:" advisory form (space after the colon) must
        # register urgency on its own, not only via a co-occurring phrase.
        value = item("Urgent: apply the emergency patch for the VPN flaw")

        action = server.actionability_details(value, SOURCE, set())

        self.assertIn("Urgent containment", action["reasons"])
        self.assertGreaterEqual(action["score"], server.ACTIONABILITY_THRESHOLD)

    def test_level_boundaries_and_score_cap(self):
        # KEV(60)+CVE(15)+critical(30)+urgent(35) saturates and clamps at 100.
        maxed = item("Critical remote code execution — urgent: patch now",
                     cves=["CVE-2026-1"])
        action = server.actionability_details(maxed, SOURCE, {"CVE-2026-1"})
        self.assertEqual(action["score"], 100)
        self.assertEqual(action["level"], "critical")

        # exploited(45) alone -> "high" band (>=45, <70).
        high = item("Flaw is being actively exploited", topics=["exploited"])
        self.assertEqual(
            server.actionability_details(high, SOURCE, set())["level"], "high")

        # remediation(20) alone -> below threshold -> "low".
        low = item("Vendor ships a patch for its collaboration tool")
        self.assertEqual(
            server.actionability_details(low, SOURCE, set())["level"], "low")

    def test_cached_text_score_matches_uncached(self):
        # The cached action_text_score fast path must equal a fresh computation.
        title = "Critical authentication bypass; emergency patch released"
        fresh = item(title, cves=["CVE-2026-2"])
        cached = dict(fresh)
        cached["action_text_score"], cached["action_text_reasons"] = \
            server._action_text_score(title, "")
        kev = {"CVE-2026-2"}
        self.assertEqual(
            server.actionability_details(fresh, SOURCE, kev),
            server.actionability_details(cached, SOURCE, kev),
        )

    def test_general_threat_intelligence_is_not_automatically_actionable(self):
        value = item("Quarterly threat landscape review", topics=["threatintel"])

        action = server.actionability_details(value, SOURCE, set())

        self.assertEqual(action["level"], "low")


if __name__ == "__main__":
    unittest.main()
