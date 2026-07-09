# rss-sec-feed

Zero-dependency headline aggregator for cybersecurity and frontier-AI news. Single Python file, standard library only — no pip installs. Runs two ways: **hosted on GitHub Pages** (static site rebuilt on a schedule by GitHub Actions) or as a **local live server**.

## GitHub Pages hosting

`.github/workflows/pages.yml` rebuilds and deploys the site every 30 minutes (plus on every push to `main`, or manually via the Actions tab):

1. Push the repo to GitHub.
2. In the repo settings, set **Settings → Pages → Source** to **GitHub Actions** (the workflow also attempts to enable this automatically on first run).
3. The site appears at `https://<user>.github.io/<repo>/`.

Each run does one full feed sweep and writes a self-contained static site (`python3 server.py --build site`): the frontend plus `data/items.json` (last 30 days, max 6000 items), `data/breaking.json`, and `data/sources.json`. All filtering, search, and paging happen client-side, so the static page has full feature parity except the manual Refresh button (data updates when the workflow runs). A rolling Actions cache preserves `data/` between runs so first-seen timestamps survive and failing feeds keep their last-known items.

## Run locally

```sh
python3 server.py
```

Open <http://127.0.0.1:8765>. First sweep of all feeds takes ~30–60s (progress bar shown); feeds auto-refresh every 15 minutes and the Refresh button forces a sweep. The local server serves the same `data/*.json` contract dynamically, so the identical frontend runs in both modes.

Options: `--port`, `--host`, `--interval`, `--workers`, `--verbose`, `--build DIR` (see `python3 server.py -h`).

## What it does

- Aggregates **227 RSS/Atom feeds**: 213 cybersecurity sources plus 14 curated frontier-AI feeds (OpenAI, DeepMind, Google AI, Hugging Face, MIT Tech Review AI, etc.).
- **Breaking News** frontpage section: recent stories reported by multiple sources are clustered by title similarity and shared CVE ids, scored by cross-source coverage + recency + preferred boost, and pinned at the top of the All tab (heuristic only — no LLM).
- **Preferred sources** (BleepingComputer, The Hacker News, Dark Reading, Krebs on Security, The Register) are starred and boosted in the default "Top" sort; "Newest" is pure chronological.
- Tabs for **All / Cybersecurity / Frontier AI / Exploited CVEs / Threat Intel**:
  - AI-related stories from cyber outlets are cross-tagged by keyword.
  - **Exploited CVEs** — items mentioning a CVE are tagged (`CVE-YYYY-NNNN` regex) and cross-referenced against the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (refetched every 6h, cached in `data/kev.json`, failure-tolerant), plus "actively exploited / in the wild / zero-day" keyword signals.
  - **Threat Intel** — 41 research/TI sources tagged `"group": "threat-intel"` in `sources.json` (Talos, Unit 42, ZDI, Google TAG, Securelist, SANS ISC, …) plus content-keyword tagging so TI stories from general outlets also match.
- Search, per-source on/off toggles, and a source-health panel (dead feeds are marked, never fatal).
- Handles RSS 2.0, Atom, and RSS 1.0/RDF; keeps stale items when a feed temporarily fails; warm-starts from an on-disk cache (`data/`, gitignored).

## Sources

The cybersecurity list comes from the CC0 [allinfosecnews_sources](https://github.com/chanpu9/allinfosecnews_sources) list (mirror of the deleted `foorilla/allinfosecnews_sources` repo, Jan 2023 snapshot), so some long-tail feeds may show as failing in the health panel. Edit `sources.json` to add, remove, or re-flag sources.
