import unittest

import server


def item(identifier, title, ts, link=None, cves=None, relevance=40):
    return {
        "id": identifier,
        "title": title,
        "link": link or f"https://example.com/{identifier}",
        "ts": ts,
        "guessed": False,
        "summary": "Technical security report.",
        "topics": [],
        "cves": cves or [],
        "relevance": relevance,
    }


def source(identifier, preferred=False):
    return {
        "id": identifier,
        "name": identifier.title(),
        "category": "cyber",
        "preferred": preferred,
    }


class CoverageGroupingTests(unittest.TestCase):
    def test_shared_cve_groups_cross_source_coverage(self):
        rows = [
            (item("one", "Vendor patches gateway flaw", 1000,
                  cves=["CVE-2026-12345"]), source("alpha")),
            (item("two", "Attackers target edge product", 900,
                  cves=["CVE-2026-12345"]), source("beta")),
        ]

        grouped = server.group_coverage(rows)

        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0][0]["coverage_count"], 2)
        self.assertEqual(grouped[0][0]["coverage_sources_count"], 2)

    def test_similar_titles_group_without_cve(self):
        rows = [
            (item("one", "RoguePlanet zero day targets Windows Defender", 1000),
             source("alpha")),
            (item("two", "Windows Defender targeted by RoguePlanet zero-day", 900),
             source("beta")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 1)

    def test_unrelated_titles_remain_separate(self):
        rows = [
            (item("one", "Ransomware disrupts regional hospital", 1000), source("alpha")),
            (item("two", "New authentication standard published", 900), source("beta")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 2)

    def test_disjoint_cves_do_not_merge_from_similar_titles(self):
        rows = [
            (item("one", "ClamAV archive memory corruption vulnerability", 1000,
                  cves=["CVE-2026-11111"]), source("alpha")),
            (item("two", "ClamAV archive memory corruption vulnerability", 900,
                  cves=["CVE-2026-22222"]), source("beta")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 2)

    def test_templated_titles_from_same_source_do_not_merge(self):
        rows = [
            (item("one", "Multiple vulnerabilities in Chrome allow code execution", 1000),
             source("advisories")),
            (item("two", "Multiple vulnerabilities in Firefox allow code execution", 900),
             source("advisories")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 2)

    def test_similar_old_story_is_not_grouped(self):
        rows = [
            (item("one", "RoguePlanet zero day targets Windows Defender", 400000),
             source("alpha")),
            (item("two", "Windows Defender targeted by RoguePlanet zero-day", 1),
             source("beta")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 2)

    def test_tracking_parameters_do_not_split_same_url(self):
        rows = [
            (item("one", "First headline", 1000,
                  link="https://www.example.com/story/?utm_source=rss"), source("alpha")),
            (item("two", "Completely different syndicated title", 900,
                  link="https://example.com/story?ref=feed"), source("beta")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 1)

    def test_preferred_source_becomes_representative(self):
        rows = [
            (item("one", "Gateway flaw receives emergency patch", 1000,
                  cves=["CVE-2026-12345"], relevance=80), source("alpha")),
            (item("two", "Emergency fix released for gateway", 900,
                  cves=["CVE-2026-12345"], relevance=40), source("beta", preferred=True)),
        ]

        grouped = server.group_coverage(rows)

        self.assertEqual(grouped[0][1]["id"], "beta")

    def test_empty_link_returns_falsy_canonical_url(self):
        self.assertEqual(server.canonical_url(""), "")
        self.assertEqual(server.canonical_url("tag:example.com,2026:1"), "")

    def test_link_less_unrelated_items_do_not_merge(self):
        # parse_feed/normalize legitimately produce link="" for entries whose
        # only identifier is a non-http GUID; these must not collapse together.
        rows = [
            (item("one", "Ransomware disrupts regional hospital", 1000, link=""),
             source("alpha")),
            (item("two", "New quantum encryption standard drafted", 900, link=""),
             source("beta")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 2)

    def test_templated_advisories_across_sources_do_not_merge(self):
        # Different products, identical advisory template, different feeds.
        rows = [
            (item("one", "Multiple vulnerabilities in Google Chrome allow "
                         "arbitrary code execution", 1000), source("cert-a")),
            (item("two", "Multiple vulnerabilities in Mozilla Firefox allow "
                         "arbitrary code execution", 900), source("cert-b")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 2)

    def test_same_story_across_sources_still_merges(self):
        # The boilerplate filter must not suppress genuine cross-source coverage.
        rows = [
            (item("one", "RoguePlanet zero day targets Windows Defender", 1000),
             source("alpha")),
            (item("two", "Windows Defender targeted by RoguePlanet zero-day", 900),
             source("beta")),
        ]

        self.assertEqual(len(server.group_coverage(rows)), 1)


if __name__ == "__main__":
    unittest.main()
