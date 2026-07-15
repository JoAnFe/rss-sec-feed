import unittest

import server


def source(category="cyber", preferred=False, group=None):
    value = {"category": category, "preferred": preferred}
    if group:
        value["group"] = group
    return value


class RelevanceScoreTests(unittest.TestCase):
    def test_low_signal_story_is_suppressed(self):
        score = server.relevance_score(
            source(),
            "Anker charger discount available this weekend",
            "The accessory is on sale for a lower price.",
        )
        self.assertLess(score, server.RELEVANCE_THRESHOLD)

    def test_preferred_source_alone_does_not_make_story_relevant(self):
        score = server.relevance_score(
            source(preferred=True),
            "More countries consider social-media age restrictions",
        )
        self.assertLess(score, server.RELEVANCE_THRESHOLD)

    def test_medium_security_signal_reaches_threshold(self):
        score = server.relevance_score(
            source(),
            "New authentication guidance for enterprise administrators",
        )
        self.assertGreaterEqual(score, server.RELEVANCE_THRESHOLD)

    def test_cve_and_vulnerability_score_highly(self):
        score = server.relevance_score(
            source(),
            "Critical vulnerability CVE-2026-12345 affects edge gateways",
            cves=["CVE-2026-12345"],
        )
        self.assertGreaterEqual(score, 60)

    def test_active_exploitation_scores_highly_without_cve(self):
        score = server.relevance_score(
            source(),
            "Zero-day attack is being actively exploited",
            topics=["exploited"],
        )
        self.assertGreaterEqual(score, 50)

    def test_curated_ai_feed_is_relevant_by_default(self):
        score = server.relevance_score(
            source(category="ai"),
            "Introducing a new foundation model",
            topics=["ai"],
        )
        self.assertGreaterEqual(score, server.RELEVANCE_THRESHOLD)

    def test_ai_industry_news_is_not_suppressed_as_low_signal(self):
        # Funding/earnings/layoffs are legitimate frontier-AI news on a curated
        # AI feed and must not trip the low-signal penalty.
        for title in ("OpenAI closes a $40B funding round",
                      "AI lab announces layoffs across its research org",
                      "Chipmaker earnings beat on surging AI demand"):
            score = server.relevance_score(source(category="ai"), title, topics=["ai"])
            self.assertGreaterEqual(score, server.RELEVANCE_THRESHOLD, title)

    def test_low_signal_penalty_still_applies_to_cyber_feeds(self):
        # The exemption is scoped to AI feeds; general low-signal cyber-feed
        # stories stay suppressed.
        score = server.relevance_score(
            source(), "Best laptop deals and discounts this weekend")
        self.assertLess(score, server.RELEVANCE_THRESHOLD)

    def test_edge_device_disclosure_outranks_generic_vulnerability(self):
        # A vulnerability disclosure naming edge/perimeter gear is prioritised
        # over an otherwise-identical generic disclosure (kept below the 100 cap
        # so the bonus is observable).
        edge = server.relevance_score(
            source(), "FortiGate remote code execution vulnerability disclosed")
        generic = server.relevance_score(
            source(), "Internal tool remote code execution vulnerability disclosed")
        self.assertEqual(edge - generic, server.EDGE_RELEVANCE_BONUS)

    def test_edge_mention_without_vuln_context_is_not_boosted(self):
        # A passing product mention with no vulnerability signal gets no boost.
        with_edge = server.relevance_score(source(), "Netgear unveils new router lineup")
        without_edge = server.relevance_score(source(), "Company unveils new product lineup")
        self.assertEqual(with_edge, without_edge)

    def test_threat_intelligence_source_is_relevant_by_default(self):
        score = server.relevance_score(
            source(group="threat-intel"),
            "Technical analysis of a new loader",
        )
        self.assertGreaterEqual(score, server.RELEVANCE_THRESHOLD)

    def test_old_cache_item_gets_score_on_read(self):
        item = {
            "title": "Ransomware campaign targets healthcare providers",
            "summary": "Incident responders observed credential theft.",
            "topics": ["threatintel"],
            "cves": [],
        }
        self.assertGreaterEqual(
            server.item_relevance(item, source()),
            server.RELEVANCE_THRESHOLD,
        )

    def test_smart_sort_diversifies_high_volume_sources(self):
        rows = []
        for index in range(10):
            rows.append(({"id": f"bulk-{index}"}, {"id": "bulk"}))
        for index in range(60):
            rows.append(({"id": f"other-{index}"}, {"id": f"other-{index}"}))

        diversified = server.diversify_smart(rows)
        first_window = diversified[: server.SMART_DIVERSITY_WINDOW]
        bulk_count = sum(1 for _, src in first_window if src["id"] == "bulk")

        self.assertEqual(bulk_count, server.SMART_MAX_PER_SOURCE)
        self.assertEqual(len(diversified), len(rows))


if __name__ == "__main__":
    unittest.main()
