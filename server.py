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
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_ITEMS_PER_FEED = 50
PREFERRED_BOOST_SECONDS = 12 * 3600  # "smart" sort: preferred items float as if 12h fresher

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

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_REFRESH_SECONDS = 6 * 3600  # refetch the KEV catalog at most every 6h

BREAKING_WINDOW_SECONDS = 48 * 3600
BREAKING_MAX = 5
BREAKING_MIN_SOURCES = 2   # a cluster needs this many distinct sources to lead
BREAKING_POOL_MAX = 2000   # newest in-window items considered for clustering
SIM_MIN_OVERLAP = 3        # shared title tokens required to join a cluster
SIM_THRESHOLD = 0.6        # overlap coefficient threshold
CVE_JOIN_MAX = 3           # CVE-based joining only for items this focused
STOPWORDS = frozenset(
    """a an and are as at be by for from has have how in is it its new of on or
    over than that the this to via vs was what when why will with you your
    after more say says said report reports researchers hackers attackers
    security update patch patches now could may 2024 2025 2026""".split()
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
KEV = {"cves": set(), "fetched_at": 0.0}       # CVE ids in the CISA KEV catalog
BREAKING = {"clusters": [], "computed_at": 0.0}
WAKE = threading.Event()
ARGS = None


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
        out.append({
            "id": iid,
            "title": r["title"],
            "link": r["link"] or (r["guid"] if r["guid"].startswith("http") else ""),
            "ts": ts,
            "guessed": guessed,
            "summary": r["summary"],
            "topics": topics,
            "cves": cves,
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


def save_kev():
    os.makedirs(ARGS.data, exist_ok=True)
    with STATE_LOCK:
        payload = {"fetched_at": KEV["fetched_at"], "count": len(KEV["cves"]),
                   "cves": sorted(KEV["cves"])}
    tmp = kev_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(payload))
    os.replace(tmp, kev_path())


def load_kev():
    try:
        with open(kev_path(), encoding="utf-8") as fh:
            payload = json.load(fh)
        cves = {c.upper() for c in payload.get("cves", []) if isinstance(c, str)}
        with STATE_LOCK:
            KEV.update(cves=cves, fetched_at=float(payload.get("fetched_at", 0)))
        print(f"[kev] warm start: {len(cves)} exploited CVEs from previous run")
    except FileNotFoundError:
        pass
    except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
        print(f"[kev] ignoring unreadable kev cache: {exc}")


def refresh_kev():
    if time.time() - KEV["fetched_at"] < KEV_REFRESH_SECONDS:
        return
    try:
        payload = json.loads(fetch_bytes(KEV_URL, timeout=20))
        cves = {v["cveID"].upper() for v in payload.get("vulnerabilities", [])
                if v.get("cveID")}
        if not cves:
            raise ValueError("KEV catalog parsed but empty")
        with STATE_LOCK:
            KEV.update(cves=cves, fetched_at=time.time())
        save_kev()
        print(f"[kev] {len(cves)} exploited CVEs loaded")
    except Exception as exc:  # noqa: BLE001 — never fatal; keep old set, retry next sweep
        print(f"[kev] fetch failed, keeping {len(KEV['cves'])} cached: {exc}")


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


def _pick_rep(members):
    return max(members, key=lambda m: (m["preferred"], not m["guessed"],
                                       len(m["summary"])))


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
                 + 2.0 * max(0.0, 1 - age_h / 48))
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
    if "exploited" not in topics and any(c in kev for c in it.get("cves", ())):
        topics.append("exploited")
    if "threatintel" not in topics and src.get("group") == "threat-intel":
        topics.append("threatintel")
    return topics


def collect_items(tab="all", q="", exclude=None, sort="smart"):
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
    seen, out = set(), []
    for it, src in rows:
        k = it["link"] or it["id"]
        if k in seen:
            continue
        seen.add(k)
        out.append((it, src))
    if sort == "latest":
        out.sort(key=lambda p: p[0]["ts"], reverse=True)
    else:  # smart: recency + preferred boost
        out.sort(key=lambda p: p[0]["ts"] + (PREFERRED_BOOST_SECONDS if p[1]["preferred"] else 0),
                 reverse=True)
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
    items = [{
        "id": it["id"], "title": it["title"], "link": it["link"],
        "ts": it["ts"], "guessed": it.get("guessed", False),
        "summary": it["summary"], "topics": effective_topics(it, src, kev),
        "cves": it.get("cves", []),
        "source": src["id"], "source_name": src["name"],
        "category": src["category"], "preferred": src["preferred"],
        "site": src.get("site") or it["link"],
    } for it, src in page]
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
    ARGS = ap.parse_args()

    load_sources()
    load_cache()
    load_kev()
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
