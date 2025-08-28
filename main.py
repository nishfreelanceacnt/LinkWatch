import os
import re
import io
import json
import time
import uuid
import math
import hashlib
import sqlite3
import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, urlunsplit

import requests
from fastapi import FastAPI, Request, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.middleware.gzip import GZipMiddleware

# Optional Postgres
try:
    import psycopg2  # type: ignore
    HAS_PG = True
except Exception:
    HAS_PG = False

APP_VERSION = "0.3.0"

# -------------------- Config --------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_IS_PG = bool(DATABASE_URL and DATABASE_URL.startswith(("postgres://", "postgresql://")))
SQLITE_PATH = os.getenv("SQLITE_PATH", "linkwatch.db")

MAX_PAGES_DEFAULT = int(os.getenv("LW_MAX_PAGES", "150"))
REQUEST_TIMEOUT = float(os.getenv("LW_TIMEOUT", "12"))
USER_AGENT = os.getenv("LW_USER_AGENT", "LinkWatchBot/1.0 (+https://example.com)")
LARGE_BYTES = int(os.getenv("LW_LARGE_BYTES", str(2_000_000)))  # 2MB default

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

app = FastAPI(title="LinkWatch", version=APP_VERSION)
app.add_middleware(GZipMiddleware)


# -------------------- DB helpers --------------------
def db_conn():
    if DB_IS_PG:
        if not HAS_PG:
            raise RuntimeError("psycopg2 is required for Postgres; install psycopg2-binary or unset DATABASE_URL")
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(SQLITE_PATH)


def db_init():
    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    id SERIAL PRIMARY KEY,
                    url TEXT NOT NULL,
                    status_code INT,
                    checked_at TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id UUID PRIMARY KEY,
                    url TEXT NOT NULL,
                    report_data JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            con.commit()
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    status_code INT,
                    checked_at TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    report_data TEXT,
                    created_at TEXT
                )
            """)
            con.commit()


def report_insert(report_id: str, url: str, report_data: Dict):
    created = datetime.datetime.utcnow().isoformat() + "Z"
    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO reports(id, url, report_data, created_at) VALUES (%s, %s, %s, %s)",
                (report_id, url, json.dumps(report_data), created),
            )
            con.commit()
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO reports(id, url, report_data, created_at) VALUES (?, ?, ?, ?)",
                (report_id, url, json.dumps(report_data), created),
            )
            con.commit()


def report_get(report_id: str) -> Optional[Dict]:
    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("SELECT report_data FROM reports WHERE id=%s", (report_id,))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("SELECT report_data FROM reports WHERE id=?", (report_id,))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])


# -------------------- Utilities --------------------
ABSOLUTE_URL_RE = re.compile(r'^(?:[a-z][a-z0-9+\-.]*:)?//', re.I)


def same_host(u1: str, u2: str) -> bool:
    try:
        return urlparse(u1).netloc.lower() == urlparse(u2).netloc.lower()
    except Exception:
        return False


def extract_links(html: str, base: str) -> Tuple[List[str], List[str]]:
    """
    Very lightweight extraction of href/src values. Returns (page_links, asset_links).
    """
    hrefs = re.findall(r'''href\s*=\s*["']([^"']+)["']''', html, flags=re.I)
    srcs = re.findall(r'''src\s*=\s*["']([^"']+)["']''', html, flags=re.I)

    def norm(u: str) -> str:
        u = u.strip()
        if not u or u.startswith("javascript:") or u.startswith("mailto:") or u.startswith("#"):
            return ""
        if ABSOLUTE_URL_RE.match(u):
            return u
        try:
            return urljoin(base, u)
        except Exception:
            return ""

    page_links: List[str] = []
    asset_links: List[str] = []
    for h in hrefs:
        nu = norm(h)
        if not nu:
            continue
        # consider anything with an extension commonly navigable as pages as "page"
        page_links.append(nu)

    for s in srcs:
        nu = norm(s)
        if not nu:
            continue
        asset_links.append(nu)

    # de-dup
    page_links = list(dict.fromkeys(page_links))
    asset_links = list(dict.fromkeys(asset_links))
    return page_links, asset_links


def is_mixed(page_url: str, asset_urls: List[str]) -> bool:
    # mixed content only relevant if page is https
    if urlparse(page_url).scheme.lower() != "https":
        return False
    for a in asset_urls:
        try:
            if urlparse(a).scheme.lower() == "http":
                return True
        except Exception:
            continue
    return False


def fetch_url(u: str) -> Tuple[int, int, float, int]:
    """
    Returns: (status_code, bytes_len, elapsed_seconds, redirect_count)
    """
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    t0 = time.time()
    try:
        r = requests.get(u, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        elapsed = max(0.0, time.time() - t0)
        status = r.status_code
        body_len = len(r.content or b"")
        redirects = len(r.history or [])
        return status, body_len, elapsed, redirects
    except requests.RequestException:
        # Consider as broken
        return 0, 0, max(0.0, time.time() - t0), 0


def crawl(base_url: str, max_pages: int = MAX_PAGES_DEFAULT) -> Dict:
    """
    BFS limited crawl on same host. Evaluates:
      - page status, size, time, redirects
      - broken links (status 0 or >=400)
      - mixed content (http assets on https page)
      - large pages (bytes > LARGE_BYTES)
    """
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Enter a full URL with http(s) scheme")

    base_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))

    visited_pages: Dict[str, Dict] = {}
    queue: List[str] = [base_url]
    issues: List[Dict] = []

    while queue and len(visited_pages) < max_pages:
        cur = queue.pop(0)
        if cur in visited_pages:
            continue

        status, body_len, elapsed, redirects = fetch_url(cur)
        # Best effort HTML detection: look at content-type only if we got a response
        content_type = ""
        try:
            # A lightweight HEAD (optional). Skip to keep simple/time-safe.
            pass
        except Exception:
            pass

        record = {
            "url": cur,
            "status": status,
            "bytes": body_len,
            "time": round(elapsed * 1000),  # ms
            "redirects": redirects,
            "title": "",  # can be filled if desired by parsing <title>; skipping heavy parse
        }
        visited_pages[cur] = record

        # Broken page?
        if status == 0 or status >= 400:
            issues.append({
                "type": "broken",
                "from": cur,
                "to": cur,
                "status": status,
                "redirects": redirects,
                "mixed": False
            })
            continue  # don't attempt to parse links on broken

        # If looks like HTML, try to extract links & assets
        # A heuristic: treat as HTML when body contains <html> or <head> or <body>
        body_sample = ""
        try:
            # Limit sample to keep memory small
            body_sample = requests.get(cur, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT).text[:200000]
        except Exception:
            body_sample = ""

        if ("<html" in body_sample.lower()) or ("<head" in body_sample.lower()) or ("<body" in body_sample.lower()):
            page_links, asset_links = extract_links(body_sample, cur)

            # Mixed content?
            if is_mixed(cur, asset_links):
                issues.append({
                    "type": "mixed",
                    "from": cur,
                    "to": "(assets)",
                    "status": status,
                    "redirects": redirects,
                    "mixed": True
                })

            # Large page?
            if body_len > LARGE_BYTES:
                issues.append({
                    "type": "large",
                    "from": cur,
                    "to": cur,
                    "status": status,
                    "redirects": redirects,
                    "mixed": False
                })

            # Follow only same-host pages
            for link in page_links:
                try:
                    if same_host(base_url, link):
                        if link not in visited_pages and link not in queue:
                            queue.append(link)
                except Exception:
                    continue

            # Check redirects and external broken links referenced by the page quickly (shallow)
            # Limit shallow external checks to a small number per page to keep scans fast
            shallow_checks = 0
            for link in page_links[:30]:
                if shallow_checks >= 10:
                    break
                st, _, _, redirs = fetch_url(link)
                if st == 0 or st >= 400:
                    issues.append({
                        "type": "broken",
                        "from": cur,
                        "to": link,
                        "status": st,
                        "redirects": redirs,
                        "mixed": False
                    })
                elif redirs > 0:
                    issues.append({
                        "type": "redirect",
                        "from": cur,
                        "to": link,
                        "status": st,
                        "redirects": redirs,
                        "mixed": False
                    })
                shallow_checks += 1
        else:
            # Non-HTML page considered large if bytes exceed threshold
            if body_len > LARGE_BYTES:
                issues.append({
                    "type": "large",
                    "from": cur,
                    "to": cur,
                    "status": status,
                    "redirects": redirects,
                    "mixed": False
                })

    pages = list(visited_pages.values())

    # Totals
    total_pages = len(pages)
    broken_count = sum(1 for i in issues if i["type"] == "broken")
    redirect_count = sum(1 for i in issues if i["type"] == "redirect")
    mixed_count = sum(1 for i in issues if i["type"] == "mixed")
    large_count = sum(1 for i in issues if i["type"] == "large")

    report = {
        "url": base_url,
        "summary": {
            "total_pages": total_pages,
            "broken": broken_count,
            "redirects": redirect_count,
            "mixed": mixed_count,
            "large": large_count
        },
        "issues": issues,
        "pages": pages
    }
    return report


# -------------------- HTML UI --------------------
def _head(title: str) -> str:
    return (
        "<meta charset='utf-8'/>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'/>"
        f"<title>{title}</title>"
        "<style>"
        ":root{--bg:#0b1020;--card:#121933;--muted:#9ab0df;--text:#eef2ff;--accent:#6ea8fe}"
        "body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto}"
        ".wrap{max-width:960px;margin:36px auto;padding:0 16px}"
        ".card{background:var(--card);border-radius:14px;padding:20px;box-shadow:0 4px 24px rgba(0,0,0,.25)}"
        "h1{margin:0 0 10px} p{color:var(--muted)}"
        "label{display:block;margin:10px 0 6px;color:#cbd5ff}"
        "input,button{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:var(--text)}"
        "button{background:var(--accent);border:none;color:#0b1020;font-weight:700;cursor:pointer}"
        "table{width:100%;border-collapse:collapse;margin-top:10px}"
        "th,td{padding:8px;border-bottom:1px solid #233366;text-align:left}"
        ".grid{display:grid;gap:12px}"
        "@media(min-width:760px){.grid{grid-template-columns:1.2fr .8fr}}"
        ".pill{display:inline-block;background:#0a1638;border:1px solid #24336a;border-radius:999px;padding:4px 8px;margin-right:6px;color:#a9b8ee}"
        "a{color:#9cc2ff}"
        ".hint{color:var(--muted);font-size:14px}"
        "</style>"
    )


def _home_html() -> str:
    return (
        "<!doctype html><html><head>" + _head("LinkWatch — check your links") + "</head><body>"
        "<div class='wrap'>"
        "<div class='card'>"
        "<h1>LinkWatch</h1>"
        "<p>Scan a site (same host) for broken links, redirects, mixed content, and large pages.</p>"
        "<form method='post' action='/scan'>"
        "<label>Site URL</label>"
        "<input name='url' placeholder='https://example.com/'/>"
        "<label class='hint'>Max pages to crawl (optional)</label>"
        "<input name='max_pages' type='number' min='1' placeholder='150'/>"
        "<div style='margin-top:10px'><button type='submit'>Scan</button></div>"
        "</form>"
        "<p class='hint' style='margin-top:8px'>You can also call the API: <code>POST /api/scan</code> with JSON <code>{\"url\":\"https://...\",\"max_pages\":150}</code></p>"
        "</div>"
        "</div></body></html>"
    )


def _report_html(url: str, rid: str, summary: Dict) -> str:
    return (
        "<!doctype html><html><head>" + _head("LinkWatch — Report") + "</head><body>"
        "<div class='wrap'>"
        "<div class='card'>"
        f"<h1>Report</h1><p><strong>{url}</strong></p>"
        f"<p class='pill'>pages: {summary['total_pages']}</p>"
        f"<span class='pill'>broken: {summary['broken']}</span>"
        f"<span class='pill'>redirects: {summary['redirects']}</span>"
        f"<span class='pill'>mixed: {summary['mixed']}</span>"
        f"<span class='pill'>large: {summary['large']}</span>"
        "<p style='margin-top:10px'>"
        f"<a href='/report/{rid}.json'>Download JSON</a> &nbsp;|&nbsp; "
        f"<a href='/report/{rid}.csv'>Download CSV (issues)</a>"
        "</p>"
        "<p class='hint'>Tip: Use the CSV to bulk-fix broken links.</p>"
        "</div>"
        "</div></body></html>"
    )


# -------------------- Routes --------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(_home_html())


@app.post("/scan", response_class=HTMLResponse)
def scan_form(url: str = Form(...), max_pages: Optional[int] = Form(None)):
    url = (url or "").strip()
    maxp = max_pages or MAX_PAGES_DEFAULT
    report = crawl(url, maxp)
    rid = str(uuid.uuid4())
    report_insert(rid, report["url"], report)
    return HTMLResponse(_report_html(report["url"], rid, report["summary"]))


@app.post("/api/scan")
def api_scan(payload: Dict):
    url = (payload.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Missing url")
    maxp = int(payload.get("max_pages") or MAX_PAGES_DEFAULT)
    report = crawl(url, maxp)
    rid = str(uuid.uuid4())
    report_insert(rid, report["url"], report)
    return {"id": rid, "report": report}


@app.get("/report/{rid}.json")
def report_json(rid: str):
    data = report_get(rid)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse(data)


@app.get("/report/{rid}.csv")
def report_csv(rid: str):
    data = report_get(rid)
    if not data:
        raise HTTPException(status_code=404, detail="Report not found")
    # CSV of issues
    out = io.StringIO()
    out.write("type,from,to,status,redirects,mixed\n")
    for i in data.get("issues", []):
        row = [
            i.get("type", ""),
            i.get("from", ""),
            i.get("to", ""),
            str(i.get("status", "")),
            str(i.get("redirects", "")),
            "yes" if i.get("mixed") else "no",
        ]
        # naive CSV escaping
        out.write(",".join('"' + v.replace('"', '""') + '"' for v in row) + "\n")
    out.seek(0)
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv")


# -------------------- SEO & health --------------------
@app.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    return PlainTextResponse(f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n")


@app.get("/sitemap.xml")
def sitemap(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    urls = ["/", "/scan"]
    items = "".join(f"<url><loc>{base}{p}</loc></url>" for p in urls)
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{items}</urlset>"""
    return HTMLResponse(xml, media_type="application/xml")


@app.get("/healthz")
def healthz():
    driver = "postgres" if DB_IS_PG else "sqlite"
    return {"ok": True, "version": APP_VERSION, "db": driver}


# -------------------- Startup --------------------
@app.on_event("startup")
def _startup():
    # Helpful startup log
    if DB_IS_PG:
        print("[startup] Using Postgres (DATABASE_URL set)")
    else:
        print(f"[startup] Using SQLite at {SQLITE_PATH}")
    db_init()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
