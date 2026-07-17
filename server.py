#!/usr/bin/env python3
"""
rss-sec-feed — local cybersecurity + frontier-AI headline aggregator.

Zero dependencies (Python 3.9+ standard library only).

Run:            python3 server.py
Then open:      http://127.0.0.1:8765

Options:
  --port 8765          listen port
  --host 127.0.0.1     bind address (use 0.0.0.0 to expose on LAN)
  --sources PATH       sources file (default: sources.json next to this script)
  --data DIR           cache directory (default: ./data)
  --interval 900       seconds between background refresh sweeps
  --workers 16         concurrent feed fetches
  --verbose            log per-feed errors
"""

import argparse
import concurrent.futures
import email.utils
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from datetime import datetime, timedelta, timezone
from html import unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 rss-sec-feed/1.0"
)
# Honest client identifier for JSON APIs. The browser-spoofing USER_AGENT above
# (used for RSS feeds) is rejected with HTTP 400 by FIRST's EPSS API/WAF, so API
# calls must not reuse it.
API_USER_AGENT = "rss-sec-feed/1.0 (+https://github.com/JoAnFe/rss-sec-feed)"
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_ITEMS_PER_FEED = 50
PREFERRED_BOOST_SECONDS = 12 * 3600  # "smart" sort: preferred items float as if 12h fresher
RELEVANCE_BOOST_SECONDS = 10 * 60    # each relevance point is worth 10m in smart sort
RELEVANCE_THRESHOLD = 20             # suppress articles with no meaningful topic signal
SMART_DIVERSITY_WINDOW = 50           # diversify the first page of smart-sort results
SMART_MAX_PER_SOURCE = 3              # prevent one high-volume feed dominating Top
ACTIONABILITY_THRESHOLD = 30
ACTIONABILITY_BOOST_SECONDS = 30 * 60
EDGE_RELEVANCE_BONUS = 15    # edge/perimeter-device disclosures float up in Top sort
EDGE_ACTION_BONUS = 20       # …and are prioritised in the Actionable tab

AI_TOPIC_RE = re.compile(
    r"\b(a\.?i\.?|artificial intelligence|machine learning|deep learning|neural net\w*|"
    r"llms?|large language model\w*|genai|generative ai|gpt-?[45o]?|chatgpt|openai|"
    r"anthropic|claude|gemini|deepmind|copilot|deepfake\w*|agentic|foundation model\w*|"
    r"prompt injection)\b",
    re.IGNORECASE,
)

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

EXPLOIT_HINT_RE = re.compile(
    r"\b(actively exploited|exploited in the wild|exploitation in the wild|"
    r"under active exploitation|mass exploitation|exploitation observed|"
    r"zero-?day|0-?day)\b",
    re.IGNORECASE,
)

THREAT_INTEL_RE = re.compile(
    r"\b(threat actor\w*|apt[- ]?\d+|ta\d{3,4}|unc\d{3,5}|lazarus|iocs?|"
    r"indicators of compromise|ttps\b|c2 server\w*|command[- ]and[- ]control|"
    r"malware campaign\w*|ransomware (gang|group|operation)\w*|nation[- ]state|"
    r"cyber ?espionage|threat intel\w*|threat hunting|mitre att&ck)\b",
    re.IGNORECASE,
)

CYBER_HIGH_SIGNAL_RE = re.compile(
    r"\b(cyber(?:security|attack|crime|espionage)|vulnerabilit\w*|exploit\w*|"
    r"zero-?day|0-?day|ransomware|malware|phishing|breach(?:ed|es)?|data leak\w*|"
    r"remote code execution|rce\b|authentication bypass|privilege escalation|"
    r"supply[- ]chain attack|backdoor\w*|botnet\w*|credential (?:theft|stealing)|"
    r"security advisor\w*|patch tuesday|incident response|threat actor\w*|"
    r"hack(?:er|ers|ing|ed)|rootkit\w*|infostealer\w*|spyware)\b",
    re.IGNORECASE,
)

CYBER_MEDIUM_SIGNAL_RE = re.compile(
    r"\b(security|privacy|encrypt\w*|cryptograph\w*|identity|authentication|"
    r"authorization|password\w*|passkeys?|firewalls?|endpoint\w*|fraud|scams?|"
    r"spoof\w*|dDoS|denial[- ]of[- ]service|cross[- ]site scripting|xss\b|"
    r"sql injection|buffer overflow|memory corruption|sandbox escape|"
    r"access control|attack surface|exposure management|digital forensics)\b",
    re.IGNORECASE,
)

LOW_SIGNAL_NEWS_RE = re.compile(
    r"\b(deals?|discounts?|on sale|earnings|stock price|shares|funding round|"
    r"layoffs?|streaming|box office|smartphone review|phone review|chargers?|"
    r"televisions?|gaming console|subscription price|shopping)\b",
    re.IGNORECASE,
)

ACTION_CRITICAL_RE = re.compile(
    r"\b(critical (?:vulnerabilit\w*|flaw\w*|bug\w*|security issue\w*)|"
    r"remote code execution|arbitrary code execution|run malicious code|"
    r"authentication bypass|privilege escalation)\b",
    re.IGNORECASE,
)

ACTION_REMEDIATION_RE = re.compile(
    r"\b(patch(?:ed|es|ing)?|security update|fix(?:ed|es)?|mitigation\w*|"
    r"workaround\w*|upgrade to|update now|apply the update)\b",
    re.IGNORECASE,
)

ACTION_URGENT_RE = re.compile(
    r"(?:\burgent\b\s*:"                        # "Urgent:" advisory headlines
    r"|\burgent\s+(?:action|patch|update|warning|advisory|mitigation|response)\b"
    r"|\bemergency\s+(?:patch|update|directive|mitigation)\b"
    r"|\bshut down\b|\bdisable immediately\b|\btake offline\b"
    r"|\bisolate immediately\b|\bdisconnect immediately\b)",
    re.IGNORECASE,
)

# Internet-facing edge / perimeter gear (VPNs, firewalls, gateways) is the most
# aggressively mass-exploited attack surface, so vendor disclosures naming these
# products are prioritised. Matched against title+summary; the score bonuses are
# gated on an actual vulnerability/disclosure context (see relevance_score /
# actionability_details) so passing mentions don't get boosted.
EDGE_DEVICE_RE = re.compile(
    r"\b("
    # perimeter/edge device classes
    r"ssl[ -]?vpn|vpn (?:appliance|gateway|concentrator)|firewalls?|"
    r"(?:security|vpn|remote[ -]access|edge|perimeter) (?:gateway|appliance)s?|"
    r"load[ -]?balancers?|edge (?:device|router)s?|"
    # network/security vendors & product families frequently mass-exploited
    r"fortinet|fortios|fortigate|fortiproxy|fortimanager|forticlient|forti\w+|"
    r"ivanti|connect secure|policy secure|pulse secure|mobileiron|"
    r"palo alto|pan-os|globalprotect|"
    r"citrix|netscaler|"
    r"cisco (?:asa|firepower|ftd|ios xe|anyconnect|adaptive security)|"
    r"sonicwall|"
    r"f5 big-?ip|big-?ip|"
    r"juniper|junos|"
    r"zyxel|draytek|watchguard|barracuda|sophos (?:xg|firewall|utm)|"
    r"check ?point (?:gateway|firewall|quantum)|array networks|sangfor|"
    r"qnap|synology|mikrotik|tp-link|netgear"
    r")\b",
    re.IGNORECASE,
)

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_REFRESH_SECONDS = 6 * 3600  # refetch the KEV catalog at most every 6h

# FIRST EPSS: predicted 30-day exploitation probability per CVE — the standard
# complement to KEV's *confirmed* exploitation. Fetched for the CVEs actually in
# the corpus, batched, and cached like the KEV catalog.
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_REFRESH_SECONDS = 6 * 3600
EPSS_BATCH = 80             # CVEs per API request (keeps the query string short)
EPSS_MAX_CVES = 4000        # cap the per-sweep enrichment set
EPSS_PROB_HIGH = 0.5        # >=50% predicted exploitation -> "high"
EPSS_PCT_HIGH = 0.95        # …or top-5% of all CVEs by percentile

# Threat-intel prioritisation weights.
RANSOMWARE_ACTION_BONUS = 25       # KEV entry tied to known ransomware campaigns
EPSS_ACTION_BONUS = 15             # high predicted exploitation probability
KEV_RANK_BOOST_SECONDS = 6 * 3600          # float confirmed-exploited items up in Top
RANSOMWARE_RANK_BOOST_SECONDS = 18 * 3600  # …ransomware-linked highest
EPSS_RANK_BOOST_SECONDS = 6 * 3600         # …and likely-to-be-exploited items too

SITE_WINDOW_DAYS = 30      # static payload: drop items older than this
SITE_MAX_ITEMS = 6000      # static payload: hard cap on shipped items

BREAKING_WINDOW_SECONDS = 48 * 3600
BREAKING_MAX = 5
BREAKING_MIN_SOURCES = 2   # a cluster needs this many distinct sources to lead
BREAKING_POOL_MAX = 2000   # newest in-window items considered for clustering
SIM_MIN_OVERLAP = 3        # shared title tokens required to join a cluster
SIM_THRESHOLD = 0.6        # overlap coefficient threshold
CVE_JOIN_MAX = 3           # CVE-based joining only for items this focused
COVERAGE_WINDOW_SECONDS = 72 * 3600
COVERAGE_ALTERNATES_MAX = 12
STOPWORDS = frozenset(
    """a an and are as at be by for from has have how in is it its new of on or
    over than that the this to via vs was what when why will with you your
    after more say says said report reports researchers hackers attackers
    security update patch patches now could may 2024 2025 2026""".split()
)
# Template words shared by advisory feeds ("Multiple vulnerabilities in <X>
# allow arbitrary code execution"). Cross-source coverage matching ignores
# these so two advisories about different products don't merge on boilerplate.
ADVISORY_BOILERPLATE = frozenset(
    """multiple vulnerabilities vulnerability allow allows allowing arbitrary
    code execution remote lead leads leading could issue issues flaw flaws
    affected affecting versions version advisory advisories bulletin bulletins
    released release high critical medium severity impact""".split()
)

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

# ---------------------------------------------------------------- state

STATE_LOCK = threading.Lock()
SOURCES = {}          # id -> source dict from sources.json
FEED_STATE = {}       # id -> {status, error, last_ok, fetched_at, items: [...]}
REFRESH = {"running": False, "done": 0, "total": 0, "started": 0.0, "finished": 0.0}
KEV = {"cves": set(), "records": {}, "fetched_at": 0.0}  # id set + full KEV records
EPSS = {"scores": {}, "fetched_at": 0.0}       # CVE id -> {epss, percentile}
BREAKING = {"clusters": [], "computed_at": 0.0}
WAKE = threading.Event()
ARGS = None

# collect_items() groups the whole corpus (O(n²) clustering); feed data only
# changes on a refresh sweep, so memoize grouped results per generation. Each
# completed sweep bumps CACHE_GEN, invalidating every cached query at once.
CACHE_GEN = 0
COLLECT_LOCK = threading.Lock()
_COLLECT_CACHE = {"gen": -1, "entries": {}}


def bump_cache_gen():
    """Invalidate memoized query results after feed state changes."""
    global CACHE_GEN
    with STATE_LOCK:
        CACHE_GEN += 1


# ---------------------------------------------------------------- fetching

def fetch_bytes(url, timeout=12):
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        "Accept-Encoding": "gzip, deflate",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_FEED_BYTES)
        enc = (resp.headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_FEED_BYTES)
    elif "deflate" in enc:
        try:
            data = zlib.decompress(data)
        except zlib.error:
            data = zlib.decompress(data, -zlib.MAX_WBITS)
    return data


def fetch_json(url, timeout=20):
    """GET a JSON API with an honest client identity (see API_USER_AGENT)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": API_USER_AGENT,
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_FEED_BYTES)
        enc = (resp.headers.get("Content-Encoding") or "").lower()
    if "gzip" in enc:
        data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_FEED_BYTES)
    return json.loads(data)


# ---------------------------------------------------------------- parsing

_CTRL_BYTES = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _local(tag):
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _children(elem, name):
    return [c for c in elem if _local(c.tag) == name]


def _first_text(elem, names):
    for name in names:
        for c in elem.iter():
            if _local(c.tag) == name:
                txt = (c.text or "").strip()
                if txt:
                    return txt
    return ""


def _item_field(item, names):
    """First non-empty direct-child text matching any local name, in order."""
    for name in names:
        for c in item:
            if _local(c.tag) == name:
                txt = "".join(c.itertext()).strip()
                if txt:
                    return txt
    return ""


def _atom_link(entry):
    fallback = ""
    for c in _children(entry, "link"):
        href = (c.get("href") or "").strip()
        if not href:
            continue
        rel = (c.get("rel") or "alternate").lower()
        if rel == "alternate":
            return href
        if not fallback:
            fallback = href
    return fallback


def strip_html(text, limit=280):
    if not text:
        return ""
    text = unescape(unescape(text))
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rsplit(" ", 1)[0] + "…"
    return text


_ISO_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*"
    r"(Z|z|[+-]\d{2}:?\d{2})?"
)


def parse_date(raw):
    """Return aware-UTC datetime or None."""
    if not raw:
        return None
    raw = raw.strip()
    try:
        dt = email.utils.parsedate_to_datetime(raw)
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
    except (TypeError, ValueError, IndexError):
        pass
    m = _ISO_RE.match(raw)
    if m:
        y, mo, d, h, mi = (int(m.group(i)) for i in range(1, 6))
        s = int(m.group(6) or 0)
        tz = timezone.utc
        off = m.group(7)
        if off and off not in ("Z", "z"):
            off = off.replace(":", "")
            sign = 1 if off[0] == "+" else -1
            tz = timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5])))
        try:
            return datetime(y, mo, d, h, mi, s, tzinfo=tz).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def parse_feed(data):
    """Parse RSS 2.0 / Atom / RSS 1.0 (RDF) bytes -> list of raw item dicts."""
    data = _CTRL_BYTES.sub(b"", data.lstrip(b"\xef\xbb\xbf\r\n\t "))
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        text = data.decode("utf-8", "replace")
        text = re.sub(r"^<\?xml[^>]*\?>", "", text.lstrip(), count=1)
        root = ET.fromstring(text)  # let ParseError propagate

    kind = _local(root.tag)
    raw_items = []
    if kind == "rss":
        for ch in _children(root, "channel"):
            raw_items += _children(ch, "item")
    elif kind == "feed":
        raw_items = _children(root, "entry")
    elif kind == "rdf":
        raw_items = _children(root, "item")
    else:
        raise ValueError(f"not a feed — got <{kind}> (page may be HTML, moved, or blocked)")

    items = []
    for it in raw_items[: MAX_ITEMS_PER_FEED * 2]:
        title = strip_html(_item_field(it, ["title"]), 400)
        link = _item_field(it, ["link"])
        if not link or not link.startswith("http"):
            link = _atom_link(it) or link
        guid = _item_field(it, ["guid", "id"])
        if (not link or not link.startswith("http")) and guid.startswith("http"):
            link = guid
        if not title or not (link or guid):
            continue
        date_raw = _item_field(it, ["pubdate", "published", "updated", "date", "modified"])
        summary = strip_html(_item_field(it, ["description", "summary", "encoded", "content"]))
        items.append({"title": title, "link": link.strip(), "guid": guid,
                      "date": parse_date(date_raw), "summary": summary})
        if len(items) >= MAX_ITEMS_PER_FEED:
            break
    return items


# ---------------------------------------------------------------- refresh

def relevance_score(src, title, summary="", topics=None, cves=None):
    """Return a deterministic 0-100 article relevance score.

    Curated AI feeds start above the display threshold. Cyber articles must
    carry a content signal, come from a threat-intelligence source, or combine
    weaker source and topic signals. This keeps general stories from mixed
    feeds out of the security stream without requiring an external model.
    """
    blob = f"{title} {summary}"
    topics = set(topics or ())
    cves = set(cves or ())
    high_signal = bool(CYBER_HIGH_SIGNAL_RE.search(blob))

    score = 35 if src.get("category") == "ai" else 8
    if src.get("preferred"):
        score += 8
    if src.get("group") == "threat-intel":
        score += 12
    if cves:
        score += 30
    if "exploited" in topics:
        score += 25
    if "threatintel" in topics:
        score += 20
    if high_signal:
        score += 25
    if CYBER_MEDIUM_SIGNAL_RE.search(blob):
        score += 12
    if "ai" in topics and src.get("category") == "cyber":
        score += 5

    # Edge/perimeter-device vulnerability disclosures are top-priority reading;
    # boost only when there is a real vuln context, not a passing product mention.
    if (high_signal or cves) and EDGE_DEVICE_RE.search(blob):
        score += EDGE_RELEVANCE_BONUS

    # Curated AI feeds are trusted on-topic, so industry terms like "funding
    # round", "earnings" or "layoffs" must not suppress legitimate AI news.
    strong_context = (high_signal or cves or {"exploited", "threatintel"} & topics
                      or src.get("category") == "ai")
    if LOW_SIGNAL_NEWS_RE.search(blob) and not strong_context:
        score -= 25
    return max(0, min(100, score))


def item_relevance(it, src):
    """Read a cached score or calculate one for items from older caches."""
    if "relevance" in it:
        return int(it["relevance"])
    return relevance_score(src, it["title"], it.get("summary", ""),
                           it.get("topics", ()), it.get("cves", ()))


def _action_text_score(title, summary=""):
    """Regex-derived action signals that depend only on the article text.

    Computed once at normalize time and cached on the item (like relevance) so
    query-time actionability scoring costs a dict lookup, not several regex
    scans, under the state lock on every request.
    """
    blob = f"{title} {summary}"
    score, reasons = 0, []
    if ACTION_CRITICAL_RE.search(blob):
        score += 30
        reasons.append("Critical impact")
    if ACTION_URGENT_RE.search(blob):
        score += 35
        reasons.append("Urgent containment")
    elif ACTION_REMEDIATION_RE.search(blob):
        score += 20
        reasons.append("Remediation available")
    return score, reasons


def _is_edge(it):
    """Read the cached edge-device flag, or derive it for older cache entries."""
    if "is_edge" in it:
        return bool(it["is_edge"])
    return bool(EDGE_DEVICE_RE.search(f"{it['title']} {it.get('summary', '')}"))


def diversify_smart(rows):
    """Limit each source in the first Top window while preserving rank order."""
    selected, deferred, counts = [], [], {}
    for row in rows:
        sid = row[1]["id"]
        if (len(selected) < SMART_DIVERSITY_WINDOW
                and counts.get(sid, 0) < SMART_MAX_PER_SOURCE):
            selected.append(row)
            counts[sid] = counts.get(sid, 0) + 1
        else:
            deferred.append(row)
    return selected + deferred


def normalize(src, raw, old_by_id):
    now = datetime.now(timezone.utc)
    ceiling = now + timedelta(days=1)
    out = []
    for r in raw:
        key = r["link"] or r["guid"] or r["title"]
        iid = hashlib.sha1(f"{src['id']}|{key}".encode("utf-8", "replace")).hexdigest()[:16]
        dt = r["date"]
        guessed = False
        if dt is None or dt > ceiling:
            prev = old_by_id.get(iid)
            if prev:
                ts, guessed = prev["ts"], prev.get("guessed", False)
            else:
                ts, guessed = now.timestamp(), True
        else:
            ts = dt.timestamp()
        blob = f"{r['title']} {r['summary']}"
        topics = ["ai"] if AI_TOPIC_RE.search(blob) else []
        cves = sorted({m.upper() for m in CVE_RE.findall(blob)})
        if cves:
            topics.append("cve")
        if (cves or src["category"] == "cyber") and EXPLOIT_HINT_RE.search(blob):
            topics.append("exploited")  # keyword signal; KEV checked at query time
        if THREAT_INTEL_RE.search(blob):
            topics.append("threatintel")  # content signal; source group checked at query time
        relevance = relevance_score(src, r["title"], r["summary"], topics, cves)
        action_text_score, action_text_reasons = _action_text_score(
            r["title"], r["summary"])
        out.append({
            "id": iid,
            "title": r["title"],
            "link": r["link"] or (r["guid"] if r["guid"].startswith("http") else ""),
            "ts": ts,
            "guessed": guessed,
            "summary": r["summary"],
            "topics": topics,
            "cves": cves,
            "relevance": relevance,
            "action_text_score": action_text_score,
            "action_text_reasons": action_text_reasons,
            "is_edge": bool(EDGE_DEVICE_RE.search(blob)),
        })
    return out


def refresh_source(src):
    sid = src["id"]
    with STATE_LOCK:
        old = FEED_STATE.get(sid, {})
        old_by_id = {i["id"]: i for i in old.get("items", [])}
    try:
        data = fetch_bytes(src["feed"], timeout=12)
        items = normalize(src, parse_feed(data), old_by_id)
        if not items:
            raise ValueError("feed parsed but contained no items")
        state = {"status": "ok", "error": None, "last_ok": time.time(),
                 "fetched_at": time.time(), "items": items}
    except Exception as exc:  # noqa: BLE001 — record every failure mode per-feed
        msg = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, urllib.error.HTTPError):
            msg = f"HTTP {exc.code}"
        elif isinstance(exc, ET.ParseError):
            msg = "not valid XML (blocked, moved, or an HTML page)"
        state = {"status": "error", "error": msg[:200],
                 "last_ok": old.get("last_ok"), "fetched_at": time.time(),
                 "items": old.get("items", [])}  # keep stale items on failure
        if ARGS and ARGS.verbose:
            print(f"  [err] {sid}: {msg[:120]}")
    with STATE_LOCK:
        FEED_STATE[sid] = state


def refresh_all():
    refresh_kev()
    srcs = list(SOURCES.values())
    with STATE_LOCK:
        REFRESH.update(running=True, done=0, total=len(srcs), started=time.time())
    t0 = time.time()

    def run(src):
        refresh_source(src)
        with STATE_LOCK:
            REFRESH["done"] += 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=ARGS.workers) as pool:
        list(pool.map(run, srcs))
    with STATE_LOCK:
        REFRESH.update(running=False, finished=time.time())
        ok = sum(1 for s in FEED_STATE.values() if s["status"] == "ok")
        n = len(srcs)
    save_cache()
    try:
        refresh_epss()  # enrich the CVEs we just ingested with predicted-exploitation
    except Exception as exc:  # noqa: BLE001 — enrichment must never kill the sweep
        print(f"[epss] refresh failed: {exc}")
    bump_cache_gen()  # feed state + intel changed — invalidate memoized queries
    try:
        compute_breaking()
    except Exception as exc:  # noqa: BLE001 — clustering must never kill the sweep
        print(f"[breaking] compute failed: {exc}")
    print(f"[refresh] {n} feeds in {time.time() - t0:.1f}s — {ok} ok, {n - ok} failing")


def refresher_loop():
    while True:
        try:
            refresh_all()
        except Exception as exc:  # keep the loop alive no matter what
            print(f"[refresh] sweep crashed: {exc}")
        WAKE.wait(timeout=ARGS.interval)
        WAKE.clear()


# ---------------------------------------------------------------- cache

def cache_path():
    return os.path.join(ARGS.data, "cache.json")


def save_cache():
    os.makedirs(ARGS.data, exist_ok=True)
    with STATE_LOCK:
        payload = {"saved_at": time.time(), "feeds": FEED_STATE}
        blob = json.dumps(payload, ensure_ascii=False)
    tmp = cache_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(blob)
    os.replace(tmp, cache_path())


def load_cache():
    try:
        with open(cache_path(), encoding="utf-8") as fh:
            payload = json.load(fh)
        feeds = payload.get("feeds", {})
        with STATE_LOCK:
            for sid, st in feeds.items():
                if sid in SOURCES and isinstance(st, dict):
                    FEED_STATE[sid] = st
        n = sum(len(s.get("items", [])) for s in feeds.values())
        print(f"[cache] warm start: {n} items from previous run")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[cache] ignoring unreadable cache: {exc}")


# ---------------------------------------------------------------- KEV catalog

def kev_path():
    return os.path.join(ARGS.data, "kev.json")


def _kev_records_from_payload(payload):
    """Reduce the raw CISA KEV catalog to the fields we surface per CVE."""
    records = {}
    for v in payload.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").strip().upper()
        if not cid:
            continue
        records[cid] = {
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
            "due_date": v.get("dueDate") or "",
            "date_added": v.get("dateAdded") or "",
            "vendor": v.get("vendorProject") or "",
            "product": v.get("product") or "",
            "name": v.get("vulnerabilityName") or "",
        }
    return records


def save_kev():
    os.makedirs(ARGS.data, exist_ok=True)
    with STATE_LOCK:
        payload = {"fetched_at": KEV["fetched_at"], "count": len(KEV["cves"]),
                   "records": KEV["records"]}
    tmp = kev_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(payload))
    os.replace(tmp, kev_path())


def load_kev():
    try:
        with open(kev_path(), encoding="utf-8") as fh:
            payload = json.load(fh)
        records = payload.get("records")
        if records is None:  # migrate an older cache that stored only the id list
            records = {c.upper(): {} for c in payload.get("cves", []) if isinstance(c, str)}
        records = {c.upper(): r for c, r in records.items()
                   if isinstance(c, str) and isinstance(r, dict)}
        with STATE_LOCK:
            KEV.update(cves=set(records), records=records,
                       fetched_at=float(payload.get("fetched_at", 0)))
        print(f"[kev] warm start: {len(records)} exploited CVEs from previous run")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        print(f"[kev] ignoring unreadable kev cache: {exc}")


def refresh_kev():
    if time.time() - KEV["fetched_at"] < KEV_REFRESH_SECONDS:
        return
    try:
        payload = json.loads(fetch_bytes(KEV_URL, timeout=20))
        records = _kev_records_from_payload(payload)
        if not records:
            raise ValueError("KEV catalog parsed but empty")
        with STATE_LOCK:
            KEV.update(cves=set(records), records=records, fetched_at=time.time())
        save_kev()
        rw = sum(1 for r in records.values() if r.get("ransomware"))
        print(f"[kev] {len(records)} exploited CVEs loaded ({rw} ransomware-linked)")
    except Exception as exc:  # noqa: BLE001 — never fatal; keep old set, retry next sweep
        print(f"[kev] fetch failed, keeping {len(KEV['cves'])} cached: {exc}")


# ---------------------------------------------------------------- EPSS scores

def epss_path():
    return os.path.join(ARGS.data, "epss.json")


def _epss_scores_from_rows(rows):
    scores = {}
    for row in rows or ():
        cid = (row.get("cve") or "").strip().upper()
        if not cid:
            continue
        try:
            scores[cid] = {"epss": float(row["epss"]),
                           "percentile": float(row["percentile"])}
        except (KeyError, TypeError, ValueError):
            continue
    return scores


def save_epss():
    os.makedirs(ARGS.data, exist_ok=True)
    with STATE_LOCK:
        payload = {"fetched_at": EPSS["fetched_at"], "scores": EPSS["scores"]}
    tmp = epss_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(payload))
    os.replace(tmp, epss_path())


def load_epss():
    try:
        with open(epss_path(), encoding="utf-8") as fh:
            payload = json.load(fh)
        scores = _epss_scores_from_rows(
            {"cve": c, **v} for c, v in payload.get("scores", {}).items()
            if isinstance(c, str) and isinstance(v, dict))
        with STATE_LOCK:
            EPSS.update(scores=scores, fetched_at=float(payload.get("fetched_at", 0)))
        print(f"[epss] warm start: {len(scores)} scores from previous run")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        print(f"[epss] ignoring unreadable epss cache: {exc}")


def _corpus_cves():
    seen = set()
    with STATE_LOCK:
        for st in FEED_STATE.values():
            for it in st.get("items", []):
                for c in it.get("cves", ()):
                    seen.add(c.upper())
    return sorted(seen)


def refresh_epss():
    """Fetch EPSS scores for the CVEs currently in the corpus, batched."""
    if time.time() - EPSS["fetched_at"] < EPSS_REFRESH_SECONDS:
        return
    cves = _corpus_cves()[:EPSS_MAX_CVES]
    if not cves:
        return
    # No &limit: the API default (100) already covers a batch of EPSS_BATCH, and
    # each batch is fetched independently so one failed request can't discard the
    # scores gathered by the others.
    scores, failed = {}, 0
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i:i + EPSS_BATCH]
        url = EPSS_URL + "?cve=" + urllib.parse.quote(",".join(batch), safe=",")
        try:
            payload = fetch_json(url, timeout=20)
            scores.update(_epss_scores_from_rows(payload.get("data", [])))
        except Exception as exc:  # noqa: BLE001 — skip this batch, keep going
            failed += 1
            if ARGS and ARGS.verbose:
                print(f"  [epss] batch failed: {exc}")
    if not scores:
        print(f"[epss] no scores fetched ({failed} batches failed), keeping "
              f"{len(EPSS['scores'])} cached")
        return
    with STATE_LOCK:
        EPSS.update(scores=scores, fetched_at=time.time())
    save_epss()
    high = sum(1 for s in scores.values() if s["epss"] >= EPSS_PROB_HIGH)
    note = f", {failed} batches failed" if failed else ""
    print(f"[epss] {len(scores)} scores loaded ({high} >= {EPSS_PROB_HIGH:.0%}{note})")


# ---------------------------------------------------------------- breaking news

def title_tokens(title):
    return set(re.findall(r"[a-z0-9][a-z0-9+.#\-]{2,}", title.lower())) - STOPWORDS


def _similar(tokens, cves, seed_tokens, seed_cves):
    # CVE joining only for focused items, so Patch-Tuesday roundups listing
    # dozens of CVEs don't glue unrelated stories together
    if (cves and seed_cves and len(cves) <= CVE_JOIN_MAX
            and len(seed_cves) <= CVE_JOIN_MAX and cves & seed_cves):
        return True
    inter = len(tokens & seed_tokens)
    if inter < SIM_MIN_OVERLAP:
        return False
    return inter / max(1, min(len(tokens), len(seed_tokens))) >= SIM_THRESHOLD


_TRACKING_QUERY_KEYS = frozenset({
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
})


def canonical_url(url):
    """Normalize a story URL for duplicate detection."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        if not host:
            # No host (empty or scheme-only link): return a falsy value so
            # link-less items never collapse into one same-URL cluster.
            return ""
        if host.startswith("www."):
            host = host[4:]
        query = urllib.parse.urlencode([
            (key, value) for key, value in urllib.parse.parse_qsl(parsed.query)
            if not key.lower().startswith("utm_")
            and key.lower() not in _TRACKING_QUERY_KEYS
        ])
        path = parsed.path.rstrip("/") or "/"
        return urllib.parse.urlunsplit((parsed.scheme.lower(), host, path, query, ""))
    except (TypeError, ValueError):
        return url or ""


def _coverage_similar(tokens, cves, src_id, cluster):
    seed_cves = cluster["seed_cves"]
    shared_cves = cves & seed_cves
    if cves and seed_cves and not shared_cves:
        return False
    if (shared_cves and len(cves) <= CVE_JOIN_MAX
            and len(seed_cves) <= CVE_JOIN_MAX):
        return True
    if src_id == cluster["seed_source"]:
        return len(tokens) >= SIM_MIN_OVERLAP and tokens == cluster["seed_tokens"]
    # Cross-source titles: compare only distinctive tokens so templated advisory
    # headlines about different products ("Multiple vulnerabilities in Chrome…"
    # vs "…in Firefox…") don't merge on shared boilerplate alone.
    content = tokens - ADVISORY_BOILERPLATE
    seed_content = cluster["seed_tokens"] - ADVISORY_BOILERPLATE
    return _similar(content, cves, seed_content, seed_cves)


def group_coverage(rows):
    """Collapse near-identical articles and retain alternate coverage links."""
    clusters = []
    for it, src in sorted(rows, key=lambda row: row[0]["ts"], reverse=True):
        tokens = title_tokens(it["title"])
        cves = set(it.get("cves", ()))
        url = canonical_url(it.get("link", ""))
        for cluster in clusters:
            within_window = abs(it["ts"] - cluster["seed_ts"]) <= COVERAGE_WINDOW_SECONDS
            same_url = bool(url and url == cluster["seed_url"])
            similar = _coverage_similar(tokens, cves, src["id"], cluster)
            if same_url or (within_window and similar):
                cluster["members"].append((it, src))
                break
        else:
            clusters.append({
                "seed_ts": it["ts"], "seed_url": url,
                "seed_tokens": tokens, "seed_cves": cves,
                "seed_source": src["id"],
                "members": [(it, src)],
            })

    grouped = []
    for cluster in clusters:
        members = cluster["members"]
        rep_it, rep_src = max(
            members,
            key=lambda row: (row[1].get("preferred", False),
                             item_relevance(row[0], row[1]),
                             not row[0].get("guessed", False),
                             len(row[0].get("summary", "")), row[0]["ts"]),
        )
        merged = dict(rep_it)
        merged["ts"] = max(it["ts"] for it, _ in members)
        merged["relevance"] = max(item_relevance(it, src) for it, src in members)
        merged["topics"] = sorted({topic for it, _ in members
                                    for topic in it.get("topics", ())})
        merged["cves"] = sorted({cve for it, _ in members
                                  for cve in it.get("cves", ())})
        alternatives = []
        for alt_it, alt_src in sorted(members, key=lambda row: row[0]["ts"], reverse=True):
            if alt_it is rep_it and alt_src is rep_src:
                continue
            alternatives.append({
                "title": alt_it["title"], "link": alt_it["link"],
                "ts": alt_it["ts"], "source": alt_src["id"],
                "source_name": alt_src["name"],
                "preferred": alt_src.get("preferred", False),
            })
        merged["coverage_count"] = len(members)
        merged["coverage_sources_count"] = len({src["id"] for _, src in members})
        merged["coverage"] = alternatives[:COVERAGE_ALTERNATES_MAX]
        grouped.append((merged, rep_src))
    return grouped


def _pick_rep(members):
    return max(members, key=lambda m: (m.get("relevance", 0), m["preferred"],
                                       not m["guessed"], len(m["summary"])))


def compute_breaking():
    """Cluster recent items into cross-source stories; store the top few."""
    now = time.time()
    cutoff = now - BREAKING_WINDOW_SECONDS
    kev = KEV["cves"]
    pool, seen = [], set()
    with STATE_LOCK:
        for sid, st in FEED_STATE.items():
            src = SOURCES.get(sid)
            if not src:
                continue
            for it in st.get("items", []):
                if it["ts"] < cutoff:
                    continue
                relevance = item_relevance(it, src)
                if relevance < RELEVANCE_THRESHOLD:
                    continue
                k = it["link"] or it["id"]
                if k in seen:
                    continue
                seen.add(k)
                pool.append({
                    "id": it["id"], "title": it["title"], "link": it["link"],
                    "ts": it["ts"], "guessed": it.get("guessed", False),
                    "summary": it["summary"],
                    "topics": effective_topics(it, src, kev),
                    "cves": it.get("cves", []),
                    "source": src["id"], "source_name": src["name"],
                    "category": src["category"], "preferred": src["preferred"],
                    "relevance": relevance,
                    "site": src.get("site") or it["link"],
                })
    pool.sort(key=lambda m: m["ts"], reverse=True)
    del pool[BREAKING_POOL_MAX:]

    # greedy clustering against each cluster's seed (first, newest member) —
    # seed comparison avoids chain drift at O(items * clusters)
    clusters = []
    for m in pool:
        tokens, cves = title_tokens(m["title"]), set(m["cves"])
        for cl in clusters:
            if _similar(tokens, cves, cl["seed_tokens"], cl["seed_cves"]):
                cl["members"].append(m)
                break
        else:
            clusters.append({"seed_tokens": tokens, "seed_cves": cves,
                             "members": [m]})

    scored = []
    for cl in clusters:
        members = cl["members"]
        distinct = len({m["source"] for m in members})
        age_h = (now - max(m["ts"] for m in members)) / 3600
        score = (3.0 * (distinct - 1)
                 + (1.0 if any(m["preferred"] for m in members) else 0.0)
                 + 2.0 * max(0.0, 1 - age_h / 48)
                 + max(m["relevance"] for m in members) / 50)
        scored.append({"members": members, "sources_count": distinct,
                       "score": round(score, 2),
                       "cves": sorted({c for m in members for c in m["cves"]})})
    scored.sort(key=lambda c: c["score"], reverse=True)

    top = [c for c in scored if c["sources_count"] >= BREAKING_MIN_SOURCES]
    top = top[:BREAKING_MAX]
    if len(top) < BREAKING_MAX:  # quiet window / cold start: best singles fill in
        top += [c for c in scored
                if c["sources_count"] < BREAKING_MIN_SOURCES][: BREAKING_MAX - len(top)]
    with STATE_LOCK:
        BREAKING.update(clusters=top, computed_at=now)


def api_breaking(params):
    exclude = set(filter(None, params.get("exclude", [""])[0].split(",")))
    with STATE_LOCK:
        snapshot = BREAKING["clusters"]
        computed_at = BREAKING["computed_at"]
    out = []
    for cl in snapshot:
        members = [m for m in cl["members"] if m["source"] not in exclude]
        if not members:
            continue
        rep = _pick_rep(members)
        others = []
        for m in sorted(members, key=lambda m: m["ts"], reverse=True):
            if m["source_name"] != rep["source_name"] and m["source_name"] not in others:
                others.append(m["source_name"])
        entry = dict(rep)
        entry.update(sources_count=len({m["source"] for m in members}),
                     other_sources=others[:3], cluster_size=len(members),
                     score=cl["score"])
        out.append(entry)
        if len(out) >= BREAKING_MAX:
            break
    return {"breaking": out, "computed_at": computed_at,
            "window_hours": BREAKING_WINDOW_SECONDS // 3600}


# ---------------------------------------------------------------- queries

def is_exploited(it, kev):
    return ("exploited" in it.get("topics", ())
            or any(c in kev for c in it.get("cves", ())))


def is_threat_intel(it, src):
    return (src.get("group") == "threat-intel"
            or "threatintel" in it.get("topics", ()))


def effective_topics(it, src, kev):
    """Item topics plus query-time signals (KEV membership, source group)."""
    topics = list(it.get("topics", []))
    in_kev = any(c in kev for c in it.get("cves", ()))
    if in_kev and "kev" not in topics:
        topics.append("kev")
    if in_kev and "exploited" not in topics:
        topics.append("exploited")
    if "threatintel" not in topics and src.get("group") == "threat-intel":
        topics.append("threatintel")
    return topics


def item_intel(it, kev_records=None, epss_scores=None):
    """Threat-intel enrichment for an item's CVEs, reduced to the most severe
    signal across them: the CISA KEV record (ransomware-campaign use, remediation
    due date, vendor/product) and the FIRST EPSS exploitation probability.

    Query-time — reads the live catalogs rather than anything cached on the item,
    so a CVE newly added to KEV or a changed EPSS score is reflected immediately.
    """
    kev_records = KEV["records"] if kev_records is None else kev_records
    epss_scores = EPSS["scores"] if epss_scores is None else epss_scores
    cves = [c.upper() for c in it.get("cves", ())]
    intel = {}

    recs = [kev_records[c] for c in cves if c in kev_records]
    if recs:
        intel["kev"] = True
        intel["ransomware"] = any(r.get("ransomware") for r in recs)
        dues = sorted(r["due_date"] for r in recs if r.get("due_date"))
        if dues:
            intel["kev_due"] = dues[0]
        for r in recs:
            product = " ".join(x for x in (r.get("vendor"), r.get("product")) if x)
            if product:
                intel["kev_product"] = product
                break

    scored = [epss_scores[c] for c in cves if c in epss_scores]
    if scored:
        top = max(scored, key=lambda s: s["epss"])
        intel["epss"] = round(top["epss"], 4)
        intel["epss_pct"] = round(top["percentile"], 4)
        intel["epss_high"] = (top["epss"] >= EPSS_PROB_HIGH
                              or top["percentile"] >= EPSS_PCT_HIGH)
    return intel


def actionability_details(it, src, kev, topics=None, intel=None):
    """Score concrete defensive action signals and explain the result."""
    topics = set(topics or effective_topics(it, src, kev))
    if intel is None:
        intel = item_intel(it)
    if "action_text_score" in it:
        text_score = it["action_text_score"]
        text_reasons = list(it.get("action_text_reasons", ()))
    else:  # older cache entry without the cached field
        text_score, text_reasons = _action_text_score(
            it["title"], it.get("summary", ""))
    score, reasons = 0, []

    if "kev" in topics:
        score += 60
        reasons.append("CISA KEV")
    elif "exploited" in topics:
        score += 45
        reasons.append("Active exploitation")
    if intel.get("ransomware"):
        score += RANSOMWARE_ACTION_BONUS
        reasons.append("Ransomware campaign")
    if it.get("cves"):
        score += 15
        reasons.append("CVE identified")
    if intel.get("epss_high"):
        score += EPSS_ACTION_BONUS
        reasons.append(f"High EPSS {round(intel['epss'] * 100)}%")
    score += text_score
    reasons += text_reasons

    # A disclosure about internet-facing edge gear jumps the queue, but only when
    # it already carries an actionable signal (so a bare product mention doesn't).
    if score > 0 and _is_edge(it):
        score += EDGE_ACTION_BONUS
        reasons.append("Edge/perimeter device")

    score = min(100, score)
    if score >= 70:
        level = "critical"
    elif score >= 45:
        level = "high"
    elif score >= ACTIONABILITY_THRESHOLD:
        level = "medium"
    else:
        level = "low"
    return {"score": score, "level": level, "reasons": reasons}


def item_payload(it, src, kev):
    topics = effective_topics(it, src, kev)
    intel = item_intel(it)
    action = actionability_details(it, src, kev, topics, intel)
    payload = {
        "id": it["id"], "title": it["title"], "link": it["link"],
        "ts": it["ts"], "guessed": it.get("guessed", False),
        "summary": it["summary"], "topics": topics,
        "cves": it.get("cves", []), "relevance": item_relevance(it, src),
        "action_score": action["score"], "action_level": action["level"],
        "action_reasons": action["reasons"],
        "source": src["id"], "source_name": src["name"],
        "category": src["category"], "preferred": src["preferred"],
        "site": src.get("site") or it["link"],
    }
    if intel:
        payload["intel"] = intel
    if it.get("coverage_count", 1) > 1:
        payload.update(
            coverage_count=it["coverage_count"],
            coverage_sources_count=it.get("coverage_sources_count", 1),
            coverage=it.get("coverage", []),
        )
    return payload


def collect_items(tab="all", q="", exclude=None, sort="smart"):
    """Memoized wrapper: identical queries within one refresh generation (and
    every pagination request, which only changes offset) reuse the grouped
    result instead of re-clustering the corpus."""
    exclude = exclude or set()
    key = (tab, q or "", tuple(sorted(exclude)), sort)
    with STATE_LOCK:
        gen = CACHE_GEN
    with COLLECT_LOCK:
        if _COLLECT_CACHE["gen"] != gen:
            _COLLECT_CACHE["gen"] = gen
            _COLLECT_CACHE["entries"] = {}
        elif key in _COLLECT_CACHE["entries"]:
            return _COLLECT_CACHE["entries"][key]
    out = _collect_items_uncached(tab, q, exclude, sort)
    with COLLECT_LOCK:
        if _COLLECT_CACHE["gen"] == gen:
            _COLLECT_CACHE["entries"][key] = out
    return out


def _collect_items_uncached(tab="all", q="", exclude=None, sort="smart"):
    exclude = exclude or set()
    terms = [t for t in (q or "").lower().split() if t]
    kev = KEV["cves"]
    rows = []
    with STATE_LOCK:
        for sid, st in FEED_STATE.items():
            src = SOURCES.get(sid)
            if not src or sid in exclude:
                continue
            cat, pref, name = src["category"], src["preferred"], src["name"]
            for it in st.get("items", []):
                if item_relevance(it, src) < RELEVANCE_THRESHOLD:
                    continue
                if (tab == "actionable"
                        and actionability_details(it, src, kev)["score"]
                        < ACTIONABILITY_THRESHOLD):
                    continue
                if tab == "cyber" and cat != "cyber":
                    continue
                if tab == "ai" and not (cat == "ai" or "ai" in it["topics"]):
                    continue
                if tab == "exploited" and not is_exploited(it, kev):
                    continue
                if tab == "intel" and not is_threat_intel(it, src):
                    continue
                if terms:
                    blob = f"{it['title']} {it['summary']} {name}".lower()
                    if not all(t in blob for t in terms):
                        continue
                rows.append((it, src))
    out = group_coverage(rows)
    if sort == "latest":
        out.sort(key=lambda p: p[0]["ts"], reverse=True)
    else:  # smart: recency + source preference + article relevance/actionability
        def smart_rank(row):
            it, src = row
            rank = (it["ts"]
                    + (PREFERRED_BOOST_SECONDS if src["preferred"] else 0)
                    + item_relevance(it, src) * RELEVANCE_BOOST_SECONDS)
            # Threat-intel prioritisation across every tab: confirmed and
            # likely-exploited items float up regardless of recency.
            intel = item_intel(it)
            if intel.get("kev"):
                rank += KEV_RANK_BOOST_SECONDS
            if intel.get("ransomware"):
                rank += RANSOMWARE_RANK_BOOST_SECONDS
            if intel.get("epss_high"):
                rank += EPSS_RANK_BOOST_SECONDS
            if tab == "actionable":
                rank += (actionability_details(it, src, kev)["score"]
                         * ACTIONABILITY_BOOST_SECONDS)
            return rank

        out.sort(
            key=smart_rank,
            reverse=True,
        )
        out = diversify_smart(out)
    return out


def api_items(params):
    tab = params.get("tab", ["all"])[0]
    q = params.get("q", [""])[0]
    sort = params.get("sort", ["smart"])[0]
    exclude = set(filter(None, params.get("exclude", [""])[0].split(",")))
    try:
        offset = max(0, int(params.get("offset", ["0"])[0]))
        limit = min(300, max(1, int(params.get("limit", ["100"])[0])))
    except ValueError:
        offset, limit = 0, 100
    rows = collect_items(tab, q, exclude, sort)
    page = rows[offset: offset + limit]
    kev = KEV["cves"]
    items = [item_payload(it, src, kev) for it, src in page]
    with STATE_LOCK:
        refresh = dict(REFRESH)
        ok = sum(1 for s in FEED_STATE.values() if s.get("status") == "ok")
    return {"items": items, "total": len(rows), "offset": offset,
            "refresh": refresh, "sources_total": len(SOURCES), "sources_ok": ok,
            "generated_at": time.time()}


def api_sources():
    out = []
    with STATE_LOCK:
        for sid, src in SOURCES.items():
            st = FEED_STATE.get(sid, {})
            out.append({
                "id": sid, "name": src["name"], "site": src.get("site"),
                "feed": src["feed"], "category": src["category"],
                "preferred": src["preferred"],
                "status": st.get("status", "pending"),
                "error": st.get("error"),
                "last_ok": st.get("last_ok"),
                "items": len(st.get("items", [])),
            })
    out.sort(key=lambda s: (s["category"], not s["preferred"], s["name"].lower()))
    return {"sources": out}


# ------------------------------------------------------- static payloads
# One data contract for both modes: the GitHub Pages build writes these to
# site/data/*.json, and the local server serves the same shapes live at
# /data/*.json — the frontend cannot tell the difference (except "mode").

def payload_items(live=False):
    kev = KEV["cves"]
    cutoff = time.time() - SITE_WINDOW_DAYS * 86400
    rows = []
    with STATE_LOCK:
        for sid, st in FEED_STATE.items():
            src = SOURCES.get(sid)
            if not src:
                continue
            for it in st.get("items", []):
                if (it["ts"] < cutoff
                        or item_relevance(it, src) < RELEVANCE_THRESHOLD):
                    continue
                rows.append((it, src))
        ok = sum(1 for s in FEED_STATE.values() if s.get("status") == "ok")
        refresh = dict(REFRESH)
    rows.sort(key=lambda p: p[0]["ts"], reverse=True)
    del rows[SITE_MAX_ITEMS:]
    items = [item_payload(it, src, kev) for it, src in rows]
    payload = {"items": items, "mode": "live" if live else "static",
               "sources_total": len(SOURCES), "sources_ok": ok,
               "generated_at": time.time()}
    if live:
        payload["refresh"] = refresh
    return payload


def payload_breaking():
    with STATE_LOCK:
        clusters = BREAKING["clusters"]
        computed_at = BREAKING["computed_at"]
    return {"clusters": [{"score": c["score"], "sources_count": c["sources_count"],
                          "cves": c["cves"], "members": c["members"]}
                         for c in clusters],
            "computed_at": computed_at,
            "window_hours": BREAKING_WINDOW_SECONDS // 3600}


def build_site():
    """One-shot: sweep every feed, then write a self-contained static site."""
    refresh_all()  # fetches KEV, sweeps feeds, saves cache, computes breaking
    out = ARGS.build
    shutil.copytree(PUBLIC_DIR, out, dirs_exist_ok=True)
    open(os.path.join(out, ".nojekyll"), "w").close()
    data_dir = os.path.join(out, "data")
    os.makedirs(data_dir, exist_ok=True)
    for name, payload in (("items.json", payload_items(live=False)),
                          ("breaking.json", payload_breaking()),
                          ("sources.json", api_sources())):
        path = os.path.join(data_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        print(f"[build] {name}: {os.path.getsize(path) / 1024:.0f} KB")
    print(f"[build] site written to {out}/")


# ---------------------------------------------------------------- http

class Handler(BaseHTTPRequestHandler):
    server_version = "rss-sec-feed/1.0"

    def log_message(self, fmt, *args):
        if ARGS and ARGS.verbose:
            sys.stderr.write("[http] " + fmt % args + "\n")

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, path):
        if path == "/":
            path = "/index.html"
        fs = os.path.realpath(os.path.join(PUBLIC_DIR, path.lstrip("/")))
        if not fs.startswith(os.path.realpath(PUBLIC_DIR) + os.sep):
            return self._json({"error": "forbidden"}, 403)
        if not os.path.isfile(fs):
            return self._json({"error": "not found"}, 404)
        ctype = CONTENT_TYPES.get(os.path.splitext(fs)[1].lower(), "application/octet-stream")
        with open(fs, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path == "/api/items":
                return self._json(api_items(params))
            if parsed.path == "/api/breaking":
                return self._json(api_breaking(params))
            if parsed.path == "/api/sources":
                return self._json(api_sources())
            # same contract the static build bakes to site/data/*.json
            if parsed.path == "/data/items.json":
                return self._json(payload_items(live=True))
            if parsed.path == "/data/breaking.json":
                return self._json(payload_breaking())
            if parsed.path == "/data/sources.json":
                return self._json(api_sources())
            return self._static(parsed.path)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # never take the server down over one request
            try:
                self._json({"error": str(exc)}, 500)
            except OSError:
                pass

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path == "/api/refresh":
            with STATE_LOCK:
                running = REFRESH["running"]
            if not running:
                WAKE.set()
            return self._json({"ok": True, "already_running": running})
        return self._json({"error": "not found"}, 404)


# ---------------------------------------------------------------- main

def load_sources():
    with open(ARGS.sources, encoding="utf-8") as fh:
        data = json.load(fh)
    for src in data["sources"]:
        if src.get("feed"):
            SOURCES[src["id"]] = src
    print(f"[sources] {len(SOURCES)} feeds "
          f"({sum(1 for s in SOURCES.values() if s['category'] == 'cyber')} cyber, "
          f"{sum(1 for s in SOURCES.values() if s['category'] == 'ai')} ai, "
          f"{sum(1 for s in SOURCES.values() if s.get('group') == 'threat-intel')} threat-intel, "
          f"{sum(1 for s in SOURCES.values() if s['preferred'])} preferred)")


def main():
    global ARGS
    ap = argparse.ArgumentParser(description="Local cyber + frontier-AI headline aggregator")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--sources", default=os.path.join(BASE_DIR, "sources.json"))
    ap.add_argument("--data", default=os.path.join(BASE_DIR, "data"))
    ap.add_argument("--interval", type=int, default=900)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--build", metavar="DIR",
                    help="one-shot: sweep feeds, write a static site to DIR, exit")
    ARGS = ap.parse_args()

    load_sources()
    load_cache()
    load_kev()
    load_epss()
    if ARGS.build:
        build_site()
        return
    try:
        compute_breaking()  # populate the hero from cache before the first sweep
    except Exception as exc:  # noqa: BLE001
        print(f"[breaking] warm-start compute failed: {exc}")

    threading.Thread(target=refresher_loop, daemon=True).start()

    server = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    print(f"\n  ▶  http://{ARGS.host}:{ARGS.port}\n     Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[exit] saving cache…")
        save_cache()


if __name__ == "__main__":
    main()
