# rss-sec-feed

Local, zero-dependency headline aggregator for cybersecurity and frontier-AI news. Single Python file, standard library only — no pip installs.

## Run

```sh
python3 server.py
```

Open <http://127.0.0.1:8765>. First sweep of all feeds takes ~30–60s (progress bar shown); feeds auto-refresh every 15 minutes.

Options: `--port`, `--host`, `--interval`, `--workers`, `--verbose` (see `python3 server.py -h`).

## What it does

- Aggregates **215 RSS/Atom feeds**: 202 cybersecurity sources plus 13 curated frontier-AI feeds (OpenAI, DeepMind, Google AI, Hugging Face, MIT Tech Review AI, etc.).
- **Preferred sources** (BleepingComputer, The Hacker News, Dark Reading, Krebs on Security, The Register) are starred and boosted in the default "Top" sort; "Newest" is pure chronological.
- Tabs for **All / Cybersecurity / Frontier AI** — AI-related stories from cyber outlets are cross-tagged by keyword.
- Search, per-source on/off toggles, and a source-health panel (dead feeds are marked, never fatal).
- Handles RSS 2.0, Atom, and RSS 1.0/RDF; keeps stale items when a feed temporarily fails; warm-starts from an on-disk cache (`data/`, gitignored).

## Sources

The cybersecurity list comes from the CC0 [allinfosecnews_sources](https://github.com/chanpu9/allinfosecnews_sources) list (mirror of the deleted `foorilla/allinfosecnews_sources` repo, Jan 2023 snapshot), so some long-tail feeds may show as failing in the health panel. Edit `sources.json` to add, remove, or re-flag sources.
