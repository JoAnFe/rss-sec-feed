import unittest
from datetime import datetime, timezone

import server


SOURCE = {"id": "src", "name": "Source", "category": "cyber", "preferred": False}


class ActorExtractionTests(unittest.TestCase):
    def test_aliases_map_to_canonical_name(self):
        for text, want in [
            ("Fancy Bear targets NATO summit attendees", ["APT28"]),
            ("Forest Blizzard exploits Outlook flaw", ["APT28"]),
            ("Octo Tempest aka UNC3944 social engineering", ["Scattered Spider"]),
            ("Clop gang lists MOVEit victims", ["Cl0p"]),
        ]:
            self.assertEqual(server.extract_actors(text), want, text)

    def test_separator_and_case_variants(self):
        self.assertEqual(server.extract_actors("APT-28 phishing wave"), ["APT28"])
        self.assertEqual(server.extract_actors("apt28 spotted again"), ["APT28"])
        self.assertEqual(server.extract_actors("APT 28 campaign"), ["APT28"])

    def test_multiple_actors_dedup_in_order(self):
        text = "Fancy Bear and Cozy Bear (aka APT28) both active"
        self.assertEqual(server.extract_actors(text), ["APT28", "APT29"])

    def test_ambiguous_names_require_qualifier(self):
        # Common English words must not trigger without ransomware context.
        self.assertEqual(server.extract_actors("Children play in the park"), [])
        self.assertEqual(server.extract_actors("Greek myth: Medusa and Perseus"), [])
        self.assertEqual(server.extract_actors("Play ransomware hits city"), ["Play"])
        self.assertEqual(server.extract_actors("Medusa ransomware claims victim"),
                         ["Medusa"])

    def test_benign_text_has_no_actors(self):
        self.assertEqual(
            server.extract_actors("New authentication guidance for admins"), [])


class MalwareExtractionTests(unittest.TestCase):
    def test_families_and_aliases(self):
        for text, want in [
            ("Attackers deploy Cobalt Strike beacons", ["Cobalt Strike"]),
            ("LummaC2 infrastructure seized", ["Lumma"]),
            ("Qbot returns after takedown", ["Qakbot"]),
        ]:
            self.assertEqual(server.extract_malware(text), want, text)

    def test_ambiguous_families_require_qualifier(self):
        self.assertEqual(server.extract_malware("Flying horse Pegasus myth"), [])
        self.assertEqual(
            server.extract_malware("Pegasus spyware found on phones"), ["Pegasus"])
        self.assertEqual(server.extract_malware("The red line was crossed"), [])
        self.assertEqual(
            server.extract_malware("RedLine stealer logs sold"), ["RedLine"])


class ActorIntegrationTests(unittest.TestCase):
    def _normalize_one(self, title, summary=""):
        raw = [{"link": "https://example.com/a", "guid": "", "title": title,
                "date": datetime(2026, 7, 1, tzinfo=timezone.utc),
                "summary": summary}]
        return server.normalize(SOURCE, raw, {})[0]

    def test_normalize_caches_actors_and_tags_threatintel(self):
        it = self._normalize_one("Fancy Bear phishing wave hits embassies")
        self.assertEqual(it["actors"], ["APT28"])
        self.assertIn("threatintel", it["topics"])

    def test_normalize_caches_malware_and_tags_threatintel(self):
        it = self._normalize_one("New Mirai variant targets routers")
        self.assertEqual(it["malware"], ["Mirai"])
        self.assertIn("threatintel", it["topics"])

    def test_actor_item_qualifies_for_intel_tab(self):
        it = self._normalize_one("LockBit affiliate arrested in Spain")
        self.assertTrue(server.is_threat_intel(it, SOURCE))

    def test_plain_item_untouched(self):
        it = self._normalize_one("Vendor patches gateway flaw")
        self.assertEqual(it["actors"], [])
        self.assertEqual(it["malware"], [])
        self.assertNotIn("threatintel", it["topics"])

    def test_payload_includes_actor_and_malware_fields(self):
        it = self._normalize_one("Scattered Spider deploys Cobalt Strike")
        payload = server.item_payload(it, SOURCE, set())
        self.assertEqual(payload["actors"], ["Scattered Spider"])
        self.assertEqual(payload["malware"], ["Cobalt Strike"])

    def test_payload_omits_empty_fields(self):
        it = self._normalize_one("Vendor patches gateway flaw")
        payload = server.item_payload(it, SOURCE, set())
        self.assertNotIn("actors", payload)
        self.assertNotIn("malware", payload)

    def test_old_cache_item_derives_actors_on_read(self):
        legacy = {"title": "Fancy Bear campaign resumes", "summary": ""}
        self.assertEqual(server.item_actors(legacy), ["APT28"])

    def test_group_coverage_unions_actors_across_members(self):
        def item(identifier, source_id, **extra):
            base = {"id": identifier, "title": "Gateway flaw exploited by group",
                    "link": f"https://{source_id}.example/{identifier}",
                    "ts": 1000.0, "guessed": False, "summary": "x",
                    "topics": [], "cves": ["CVE-2026-1"], "actors": [],
                    "malware": [], "relevance": 60}
            base.update(extra)
            return base

        rows = [
            (item("one", "alpha", actors=["APT28"]),
             {"id": "alpha", "name": "Alpha", "category": "cyber", "preferred": False}),
            (item("two", "beta", malware=["Cobalt Strike"]),
             {"id": "beta", "name": "Beta", "category": "cyber", "preferred": False}),
        ]
        grouped = server.group_coverage(rows)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0][0]["actors"], ["APT28"])
        self.assertEqual(grouped[0][0]["malware"], ["Cobalt Strike"])


if __name__ == "__main__":
    unittest.main()
