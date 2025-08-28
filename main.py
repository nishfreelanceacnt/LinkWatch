# main.py
import os, re, io, csv, json, time, hashlib, smtplib, uuid, datetime
from typing import Optional, List, Dict, Tuple, Set
from urllib.parse import urlparse, urljoin, urlunsplit

import requests
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Query, Header, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse, Response as FastAPIResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# ---------- DB ----------
import sqlite3
try:
    import psycopg2
    HAS_PG = True
except Exception:
    HAS_PG = False

# ---------- Parsing ----------
try:
    from bs4 import BeautifulSoup
except Exception as e:
    raise RuntimeError("BeautifulSoup4 is required. Add to requirements.txt: beautifulsoup4") from e

# ---------- App ----------
APP_VERSION = "0.9.2"
app = FastAPI(title="LinkWatch", version=APP_VERSION)
app.add_middleware(GZipMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---------- Config ----------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
LW_DB_PATH   = os.getenv("LW_DB_PATH", "").strip() or "linkwatch.db"
DB_IS_PG     = bool(DATABASE_URL and DATABASE_URL.startswith(("postgres://", "postgresql://")))

RATE_LIMIT_PER_MIN      = int(os.getenv("RATE_LIMIT_PER_MIN", "20"))
SCAN_MAX_PAGES_FREE     = int(os.getenv("SCAN_MAX_PAGES_FREE", "150"))
SCAN_MAX_PAGES_HARD     = int(os.getenv("SCAN_MAX_PAGES_HARD", "5000"))
SCAN_TIMEOUT_SECONDS    = int(os.getenv("SCAN_TIMEOUT_SECONDS", "12"))
LW_USER_AGENT           = os.getenv("LW_USER_AGENT", f"LinkWatch/{APP_VERSION} (+https://example.com)")
PUBLIC_BASE_URL         = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")

# Analytics / verification
PLAUSIBLE_DOMAIN           = os.getenv("PLAUSIBLE_DOMAIN", "").strip()
GOOGLE_SITE_VERIFICATION   = os.getenv("GOOGLE_SITE_VERIFICATION", "").strip()

# Email (optional)
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587")) if os.getenv("SMTP_PORT") else None
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
REPORT_EMAIL_FROM = os.getenv("REPORT_EMAIL_FROM")

# ---------- Security headers ----------
class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        if PLAUSIBLE_DOMAIN:
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "img-src 'self' data:; "
                "style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline' https://plausible.io; "
                "connect-src 'self' https://plausible.io;"
            )
        return resp
app.add_middleware(SecurityHeaders)

# ---------- Helpers: DB ----------
def db_conn():
    if DB_IS_PG:
        if not HAS_PG:
            raise RuntimeError("psycopg2 not installed; needed for Postgres")
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(LW_DB_PATH)

def db_init():
    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    id SERIAL PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    title TEXT,
                    status_code INT,
                    bytes INT,
                    elapsed_ms INT,
                    redirects INT,
                    mixed INT DEFAULT 0
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    root_url TEXT NOT NULL,
                    email TEXT,
                    summary JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            con.commit()
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    title TEXT,
                    status_code INTEGER,
                    bytes INTEGER,
                    elapsed_ms INTEGER,
                    redirects INTEGER,
                    mixed INTEGER DEFAULT 0
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    root_url TEXT NOT NULL,
                    email TEXT,
                    summary TEXT,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            con.commit()

# ---------- Rate limit (simple in-memory) ----------
_rl: Dict[str, List[float]] = {}
def rate_limit_ok(bucket: str) -> bool:
    now = time.time()
    arr = [t for t in _rl.get(bucket, []) if now - t < 60.0]
    if len(arr) >= RATE_LIMIT_PER_MIN:
        _rl[bucket] = arr
        return False
    arr.append(now)
    _rl[bucket] = arr
    return True

# ---------- SEO bits ----------
def _analytics_snippet() -> str:
    if not PLAUSIBLE_DOMAIN: return ""
    return f'<script defer data-domain="{PLAUSIBLE_DOMAIN}" src="https://plausible.io/js/script.js"></script>'

def _google_verify_snippet() -> str:
    if not GOOGLE_SITE_VERIFICATION: return ""
    return f'<meta name="google-site-verification" content="{GOOGLE_SITE_VERIFICATION}"/>'

def _html_head(title: str) -> str:
    return (
        f'<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>'
        + _google_verify_snippet()
        + f"<title>{title}</title>"
        + '<link rel="icon" href="/favicon.svg">'
        + _analytics_snippet()
        + """
<style>
:root{--bg:#0b1020;--card:#121933;--muted:#8da2d0;--text:#eef2ff;--accent:#6ea8fe;}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto}
.wrap{max-width:960px;margin:40px auto;padding:0 16px}
.card{background:var(--card);border-radius:16px;padding:22px;box-shadow:0 4px 24px rgba(0,0,0,.25)}
h1{margin:0 0 6px;font-size:28px} p{margin:0 0 16px;color:var(--muted)}
header{display:flex;align-items:center;gap:12px;margin-bottom:14px}
header img{width:36px;height:36px}
nav a{color:#9cc2ff;margin-right:14px;text-decoration:none} nav a:hover{text-decoration:underline}
label{display:block;margin:12px 0 6px;color:#c8d1f5}
input,button,select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:var(--text)}
button{background:var(--accent);border:none;color:#04122d;font-weight:700;cursor:pointer}
pre{background:#0a0f24;border:1px solid #26335f;border-radius:12px;padding:14px;overflow:auto}
small{color:var(--muted)} .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #233366;text-align:left}
.stat{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.bad{color:#ef6f6c} .ok{color:#55d38a} .warn{color:#e9c46a}
.btn{display:inline-block;padding:8px 12px;border-radius:8px;border:1px solid #233366;background:#0e1630;color:#eaf0ff;text-decoration:none}
</style>
"""
    )

# ---------- Logo ----------
LOGO_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'>
  <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#6ea8fe'/><stop offset='100%' stop-color='#7bd3ff'/></linearGradient></defs>
  <rect x='16' y='16' width='224' height='224' rx='48' fill='#0e1630'/>
  <rect x='24' y='24' width='208' height='208' rx='40' fill='url(#g)' opacity='0.08'/>
  <g fill='#eaf0ff'>
    <path d='M70 120h60v16H70zM70 156h80v16H70zM70 84h100v16H70z'/>
    <circle cx='180' cy='168' r='24' fill='#6ea8fe'/>
  </g>
</svg>"""
@app.get("/favicon.svg")
def fav(): return FastAPIResponse(content=LOGO_SVG, media_type="image/svg+xml")

# ---------- Crawling ----------
ABS_LOC_RE = re.compile(r"<loc>(.*?)</loc>", re.I | re.S)
def norm_max_pages(val, fallback):
    try:
        n = int(val)
        return max(1, n)
    except Exception:
        return max(1, int(fallback))

def same_host(a: str, b: str) -> bool:
    try:
        pa, pb = urlparse(a), urlparse(b)
        return (pa.scheme, pa.hostname) == (pb.scheme, pb.hostname)
    except Exception:
        return False

def strip_fragment(u: str) -> str:
    p = urlparse(u)
    return p._replace(fragment="").geturl()

def extract_links(base_url: str, html: str) -> Set[str]:
    soup = BeautifulSoup(html, "html.parser")
    out: Set[str] = set()
    for a in soup.find_all("a", href=True):
        href = (a["href"] or "").strip()
        if not href or href.startswith("#"):
            continue
        u = urljoin(base_url, href)
        u = strip_fragment(u)
        out.add(u)
    return out

def page_title(html: str) -> Optional[str]:
    try:
        soup = BeautifulSoup(html, "html.parser")
        t = soup.find("title")
        return (t.text or "").strip() if t else None
    except Exception:
        return None

def is_mixed_content(url: str, html: str) -> bool:
    # if page is https, flag if it references http assets
    if not url.startswith("https://"):
        return False
    return "http://" in html

def fetch_sitemap_urls(site_root: str, timeout=10) -> Set[str]:
    try:
        p = urlparse(site_root)
        root = f"{p.scheme}://{p.netloc}"
        r = requests.get(root + "/sitemap.xml", timeout=timeout, headers={"User-Agent": LW_USER_AGENT})
        if r.status_code != 200:
            return set()
        text = r.text
        urls = set()
        try:
            # first pass: naive regex for <loc>…</loc>
            for m in ABS_LOC_RE.finditer(text):
                u = m.group(1).strip()
                if u: urls.add(u)
        except Exception:
            pass
        return urls
    except Exception:
        return set()

def crawl(start_url: str, max_pages: int, same_host_only: bool, seed_mode: str, timeout: int) -> List[Dict]:
    start_url = strip_fragment(start_url)
    q: List[str] = [start_url]
    visited: Set[str] = set()
    results: List[Dict] = []

    # optional sitemap seeding
    if seed_mode in ("sitemap", "auto"):
        for u in fetch_sitemap_urls(start_url, timeout=timeout):
            if same_host_only and not same_host(start_url, u):
                continue
            q.append(u)

    while q and len(visited) < max_pages:
        url = q.pop(0)
        if url in visited:
            continue
        visited.add(url)

        t0 = time.perf_counter()
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": LW_USER_AGENT}, allow_redirects=True)
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            status = r.status_code
            ctype = (r.headers.get("Content-Type") or "").lower()
            body = r.text if (status == 200 and "text/html" in ctype) else ""
            title = page_title(body) if body else None
            redirects = len(r.history)
            mixed = 1 if (body and is_mixed_content(url, body)) else 0

            results.append({
                "url": url,
                "title": title,
                "status": status,
                "bytes": len(r.content),
                "elapsed_ms": elapsed_ms,
                "redirects": redirects,
                "mixed": mixed
            })

            # Enqueue links from HTML pages
            if status == 200 and body:
                for u in extract_links(url, body):
                    if same_host_only and not same_host(start_url, u):
                        continue
                    if u not in visited and u not in q and len(visited) + len(q) < max_pages:
                        q.append(u)

        except Exception:
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            results.append({
                "url": url,
                "title": None,
                "status": 0,
                "bytes": 0,
                "elapsed_ms": elapsed_ms,
                "redirects": 0,
                "mixed": 0
            })
            continue

    return results

# ---------- Persistence ----------
def save_report(root_url: str, email: Optional[str], pages: List[Dict]) -> str:
    rid = uuid.uuid4().hex
    # Summaries
    total = len(pages)
    broken = sum(1 for p in pages if p["status"] == 0 or (p["status"] >= 400))
    redirect_issues = sum(1 for p in pages if (p["redirects"] or 0) >= 2)
    mixed_count = sum(1 for p in pages if p.get("mixed", 0))
    large_pages = sum(1 for p in pages if (p.get("bytes") or 0) > 1_000_000)

    summary = {
        "root_url": root_url,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_pages": total,
        "broken": broken,
        "redirect_issues": redirect_issues,
        "mixed": mixed_count,
        "large": large_pages,
        "version": APP_VERSION
    }

    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO reports(id, root_url, email, summary) VALUES (%s,%s,%s,%s)",
                (rid, root_url, email, json.dumps(summary))
            )
            for p in pages:
                cur.execute(
                    "INSERT INTO links(report_id,url,title,status_code,bytes,elapsed_ms,redirects,mixed) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                    (rid, p["url"], p.get("title"), p.get("status"), p.get("bytes"), p.get("elapsed_ms"),
                     p.get("redirects"), p.get("mixed"))
                )
            con.commit()
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("INSERT INTO reports(id, root_url, email, summary) VALUES (?,?,?,?)",
                        (rid, root_url, email, json.dumps(summary)))
            for p in pages:
                cur.execute(
                    "INSERT INTO links(report_id,url,title,status_code,bytes,elapsed_ms,redirects,mixed) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (rid, p["url"], p.get("title"), p.get("status"), p.get("bytes"), p.get("elapsed_ms"),
                     p.get("redirects"), p.get("mixed"))
                )
            con.commit()
    return rid

def load_report(report_id: str) -> Tuple[Dict, List[Dict]]:
    if DB_IS_PG:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("SELECT id, root_url, email, summary FROM reports WHERE id=%s", (report_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Report not found")
            summary = row[3] if isinstance(row[3], dict) else json.loads(row[3])
            cur.execute("SELECT url,title,status_code,bytes,elapsed_ms,redirects,mixed FROM links WHERE report_id=%s ORDER BY id ASC", (report_id,))
            pages = []
            for r in cur.fetchall():
                pages.append({"url": r[0], "title": r[1], "status": r[2], "bytes": r[3], "elapsed_ms": r[4], "redirects": r[5], "mixed": r[6]})
            return summary, pages
    else:
        with db_conn() as con:
            cur = con.cursor()
            cur.execute("SELECT id, root_url, email, summary FROM reports WHERE id=?", (report_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "Report not found")
            summary = json.loads(row[3]) if isinstance(row[3], (str, bytes)) else (row[3] or {})
            cur.execute("SELECT url,title,status_code,bytes,elapsed_ms,redirects,mixed FROM links WHERE report_id=? ORDER BY id ASC", (report_id,))
            pages = []
            for r in cur.fetchall():
                pages.append({"url": r[0], "title": r[1], "status": r[2], "bytes": r[3], "elapsed_ms": r[4], "redirects": r[5], "mixed": r[6]})
            return summary, pages

# ---------- Email ----------
def send_email(to_email: str, subject: str, body: str):
    if not (SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS and REPORT_EMAIL_FROM):
        return
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = REPORT_EMAIL_FROM
        msg["To"] = to_email
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception:
        # Silent fail on email in this MVP
        pass

# ---------- UI ----------
def home_html() -> str:
    return (
        "<!doctype html><html><head>"+_html_head("LinkWatch — Broken link & mixed content checker")+"</head><body>"
        "<div class='wrap'><header><img src='/favicon.svg' alt='logo'/><strong>LinkWatch</strong></header>"
        "<div class='card'><h1>Scan a site</h1>"
        "<label>Start URL</label><input id='u' placeholder='https://example.com'/>"
        "<div class='row'>"
        "<div><label>Max pages</label><input id='m' type='number' value='100'/></div>"
        "<div><label>Same host only?</label><select id='sh'><option value='1'>Yes</option><option value='0'>No</option></select></div>"
        "</div>"
        "<div class='row'>"
        "<div><label>Seed</label><select id='seed'><option value='auto'>auto (try sitemap)</option><option value='sitemap'>sitemap only</option><option value='none'>none</option></select></div>"
        "<div><label>Notify email (optional)</label><input id='e' placeholder='you@domain.com'/></div>"
        "</div>"
        "<div style='margin-top:8px'><button id='go' type='button'>Start scan</button></div>"
        "<div id='status' style='margin-top:8px'><small class='hint'>Ready.</small></div>"
        "</div>"
        "<div class='card' id='res' style='display:none;margin-top:14px'></div>"
        "</div>"
        "<script>"
        "const $=id=>document.getElementById(id);"
        "async function run(){"
        " const u=$('u').value.trim(); if(!u){$('status').innerHTML='Enter a URL.';return;}"
        " const m=parseInt($('m').value||'100',10); const sh=$('sh').value; const seed=$('seed').value; const e=$('e').value.trim();"
        " $('status').innerHTML='Running…';"
        " const q=new URLSearchParams({url:u,max_pages:String(m),same_host:sh,seed:seed}); if(e) q.set('email',e);"
        " const r=await fetch('/scan?'+q.toString()); const t=await r.text();"
        " try{const j=JSON.parse(t); $('status').innerHTML='Done';"
        "   const link=j.report_url?('<a class=\"btn\" href=\"'+j.report_url+'\">Open report</a>'):'(no report URL)';"
        "   $('res').style.display='block'; $('res').innerHTML='<h2>Report</h2><pre>'+JSON.stringify(j,null,2)+'</pre>'+link;"
        " }catch{ $('status').innerHTML='Error'; $('res').style.display='block'; $('res').innerHTML='<pre>'+t+'</pre>'; }"
        "}"
        "document.getElementById('go').addEventListener('click', run);"
        "</script>"
        "</body></html>"
    )

def report_html(summary: Dict, pages: List[Dict], rid: str) -> str:
    def num(n): return str(n)
    return (
        "<!doctype html><html><head>"+_html_head("LinkWatch — Report")+"</head><body><div class='wrap'>"
        "<header><img src='/favicon.svg' alt='logo'/><strong>LinkWatch</strong></header>"
        "<div class='card'><h1>Report</h1>"
        f"<p><strong>Root:</strong> <a href='{summary['root_url']}'>{summary['root_url']}</a></p>"
        f"<div class='stat'><div><strong>Total</strong><div>{num(summary['total_pages'])}</div></div>"
        f"<div><strong>Broken</strong><div class='bad'>{num(summary['broken'])}</div></div>"
        f"<div><strong>Redirect</strong><div class='warn'>{num(summary['redirect_issues'])}</div></div>"
        f"<div><strong>Mixed</strong><div class='warn'>{num(summary['mixed'])}</div></div>"
        f"<div><strong>Large</strong><div class='warn'>{num(summary['large'])}</div></div></div>"
        f"<p><a class='btn' href='/report.csv?id={rid}'>Download CSV (issues)</a> "
        f"<a class='btn' href='/report.json?id={rid}'>JSON</a> "
        "<a class='btn' href='/'>New scan</a></p>"
        "</div>"
        "<div class='card' style='margin-top:14px'><h2>Issues</h2>"
        "<table><thead><tr><th>Type</th><th>Title</th><th>URL</th><th>Status</th><th>Bytes</th><th>Time</th><th>Redirects</th><th>Mixed?</th></tr></thead><tbody>"
        + "".join(
            f"<tr><td>{'Broken' if (p['status']==0 or p['status']>=400) else ('Redirect' if (p.get('redirects',0)>=2) else ('Large' if (p.get('bytes',0)>1_000_000) else ('Mixed' if p.get('mixed') else '—')))}</td>"
            f"<td>{(p.get('title') or '').replace('<','&lt;').replace('>','&gt;')}</td>"
            f"<td><a href='{p['url']}'>{p['url']}</a></td>"
            f"<td>{p['status']}</td>"
            f"<td>{p.get('bytes',0)}</td>"
            f"<td>{p.get('elapsed_ms',0)} ms</td>"
            f"<td>{p.get('redirects',0)}</td>"
            f"<td>{'yes' if p.get('mixed') else ''}</td></tr>"
            for p in pages
            if (p['status']==0 or p['status']>=400) or (p.get('redirects',0)>=2) or (p.get('mixed')) or (p.get('bytes',0)>1_000_000)
        or ["<tr><td colspan='8'><em>No issues detected.</em></td></tr>"][0]
        )
        + "</tbody></table></div>"
        "<div class='card' style='margin-top:14px'><h2>Pages</h2>"
        "<table><thead><tr><th>Title</th><th>URL</th><th>Status</th><th>Bytes</th><th>Time</th><th>Redirects</th></tr></thead><tbody>"
        + "".join(
            f"<tr><td>{(p.get('title') or '').replace('<','&lt;').replace('>','&gt;')}</td>"
            f"<td><a href='{p['url']}'>{p['url']}</a></td>"
            f"<td>{p['status']}</td>"
            f"<td>{p.get('bytes',0)}</td>"
            f"<td>{p.get('elapsed_ms',0)} ms</td>"
            f"<td>{p.get('redirects',0)}</td></tr>"
            for p in pages
        )
        + "</tbody></table></div>"
        "<p class='hint' style='margin-top:10px'>By using LinkWatch you agree to reasonable crawling of your site. Respect robots.txt when enabled.</p>"
        "</div></body></html>"
    )

# ---------- Routes ----------
@app.get("/", response_class=HTMLResponse)
def home(): return HTMLResponse(home_html())

@app.get("/healthz")
def healthz(): return {"ok": True, "version": APP_VERSION}

@app.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    return PlainTextResponse("User-agent: *\nAllow: /\nSitemap: " + base + "/sitemap.xml\n")

@app.get("/sitemap.xml")
def sitemap(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    xml = (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
        f"<url><loc>{base}/</loc></url>"
        f"<url><loc>{base}/report</loc></url>"
        "</urlset>"
    )
    return FastAPIResponse(content=xml, media_type="application/xml")

@app.get("/scan", tags=["API"])
def scan(
    request: Request,
    url: str = Query(..., description="Start URL, e.g. https://example.com"),
    max_pages: Optional[int] = Query(None, ge=1, le=SCAN_MAX_PAGES_HARD),
    same_host: int = Query(1, description="1=limit to same scheme+host"),
    seed: str = Query("auto", description="auto|sitemap|none"),
    email: Optional[str] = Query(None, description="optional notify email"),
    respect_robots: int = Query(0, description="(placeholder) not enforced in this MVP")
):
    if not rate_limit_ok(request.client.host if request.client else "unknown"):
        raise HTTPException(429, "Too many requests. Slow down.")

    # normalize limits
    max_pages_eff = norm_max_pages(max_pages if max_pages is not None else SCAN_MAX_PAGES_FREE, SCAN_MAX_PAGES_FREE)
    if max_pages_eff > SCAN_MAX_PAGES_HARD:
        max_pages_eff = SCAN_MAX_PAGES_HARD

    # crawl
    pages = crawl(url, max_pages=max_pages_eff, same_host_only=bool(same_host), seed_mode=seed, timeout=SCAN_TIMEOUT_SECONDS)
    rid = save_report(url, email, pages)
    rep_url = (PUBLIC_BASE_URL or (str(request.base_url).rstrip("/"))) + f"/report?id={rid}"

    # email (optional)
    if email:
        try:
            send_email(
                email,
                "Your LinkWatch report is ready",
                f"Your report for {url} is ready.\n\nOpen: {rep_url}\n\nThanks for trying LinkWatch!"
            )
        except Exception:
            pass

    # JSON summary
    total = len(pages)
    broken = sum(1 for p in pages if p["status"] == 0 or (p["status"] >= 400))
    redirects = sum(1 for p in pages if (p.get("redirects",0) >= 2))
    mixed = sum(1 for p in pages if p.get("mixed"))
    large = sum(1 for p in pages if (p.get("bytes",0) > 1_000_000))
    return {
        "report_id": rid,
        "report_url": rep_url,
        "root_url": url,
        "total_pages": total,
        "broken": broken,
        "redirect_issues": redirects,
        "mixed": mixed,
        "large": large
    }

@app.get("/report", response_class=HTMLResponse)
def report_page(id: str = Query(...)):
    summary, pages = load_report(id)
    return HTMLResponse(report_html(summary, pages, id))

@app.get("/report.json")
def report_json(id: str = Query(...)):
    summary, pages = load_report(id)
    return {"summary": summary, "pages": pages}

@app.get("/report.csv")
def report_csv(id: str = Query(...)):
    summary, pages = load_report(id)
    # Only issues to CSV
    issues = [
        {
            "type": ("Broken" if (p["status"]==0 or p["status"]>=400) else ("Redirect" if (p.get("redirects",0)>=2) else ("Mixed" if p.get("mixed") else ("Large" if (p.get("bytes",0)>1_000_000) else "")))),
            "title": p.get("title") or "",
            "url": p["url"],
            "status": p["status"],
            "bytes": p.get("bytes",0),
            "time_ms": p.get("elapsed_ms",0),
            "redirects": p.get("redirects",0),
            "mixed": "yes" if p.get("mixed") else ""
        }
        for p in pages
        if (p["status"]==0 or p["status"]>=400) or (p.get("redirects",0)>=2) or p.get("mixed") or (p.get("bytes",0)>1_000_000)
    ]
    if not issues:
        issues = [{"type":"", "title":"", "url":"", "status":"", "bytes":"", "time_ms":"", "redirects":"", "mixed":""}]

    def gen():
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["type","title","url","status","bytes","time_ms","redirects","mixed"])
        w.writeheader(); yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for row in issues:
            w.writerow(row); yield buf.getvalue(); buf.seek(0); buf.truncate(0)

    filename = f"linkwatch_{id}.csv"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(gen(), media_type="text/csv", headers=headers)

# ---------- Startup ----------
@app.on_event("startup")
def _startup():
    db_init()
# === BEGIN LINKWATCH PATCH v0.2 (resilient fetch + debug + fixed report page) ===
# Safe: duplicate imports are fine
import os, time, json
from fastapi import Query
from fastapi.responses import HTMLResponse, JSONResponse

# ----- Resilient outbound fetch (monkey-patch requests.get) -----
try:
    LW_USER_AGENT
except NameError:
    LW_USER_AGENT = os.getenv("LW_USER_AGENT", "LinkWatch/1.0 (+https://example.com)").strip()

BROWSER_HEADERS = {
    "User-Agent": LW_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
    "Cache-Control": "no-cache",
}

# Keep the original to fall back on
try:
    _REAL_REQUESTS_GET = requests.get  # type: ignore[name-defined]
except Exception:
    _REAL_REQUESTS_GET = None

def _patched_requests_get(url, *args, **kwargs):
    """
    First try: your UA only. On exception, retry with browser-ish headers.
    Preserves kwargs (timeout, allow_redirects, etc.)
    """
    if _REAL_REQUESTS_GET is None:
        raise RuntimeError("requests not available")
    # First try: inject our UA but preserve any provided headers
    h1 = {**({"User-Agent": LW_USER_AGENT}), **(kwargs.get("headers") or {})}
    try:
        return _REAL_REQUESTS_GET(url, *args, **{**kwargs, "headers": h1})
    except Exception:
        # Second try: browser-ish
        h2 = {**BROWSER_HEADERS, **(kwargs.get("headers") or {})}
        return _REAL_REQUESTS_GET(url, *args, **{**kwargs, "headers": h2})

# Monkey-patch only if not already patched
try:
    if getattr(requests.get, "__name__", "") != "_patched_requests_get":  # type: ignore[attr-defined]
        requests.get = _patched_requests_get  # type: ignore[assignment]
except Exception:
    pass

# ----- Debug fetch endpoint -----
@app.get("/_debug/fetch")
def _debug_fetch(url: str = Query(...), timeout: int = Query(8)):
    t0 = time.perf_counter()
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)  # patched above
        info = {
            "ok": True,
            "status": r.status_code,
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
            "final_url": getattr(r, "url", url),
            "history": [{"status": h.status_code, "url": getattr(h, "url", "")} for h in getattr(r, "history", [])],
            "content_type": r.headers.get("Content-Type"),
            "bytes": len(r.content or b""),
        }
        # Include a snippet for text responses to verify what we got
        ctype = (r.headers.get("Content-Type") or "").lower()
        if "text" in ctype or "json" in ctype or "xml" in ctype:
            try:
                info["snippet"] = r.text[:2000]
            except Exception:
                pass
        return JSONResponse(info)
    except Exception as e:
        return JSONResponse(
            {"ok": False, "error": str(e), "elapsed_ms": int((time.perf_counter() - t0) * 1000)},
            status_code=502
        )

# ----- FIXED /report page (computes totals from /api/report data) -----
@app.get("/report", response_class=HTMLResponse)
def report_page(id: str):
    html = f"""
<!doctype html><html lang="en"><head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>LinkWatch — Report</title>
  <style>
    body{{margin:0;font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto;background:#0b1020;color:#eef2ff}}
    .wrap{{max-width:960px;margin:28px auto;padding:0 16px}}
    .card{{background:#121933;border:1px solid #233366;border-radius:14px;padding:16px;box-shadow:0 4px 24px rgba(0,0,0,.25)}}
    h1{{margin:0 0 8px}} small{{color:#9fb1e8}}
    .grid{{display:grid;gap:12px}} @media(min-width:720px){{.grid{{grid-template-columns:repeat(3,1fr)}}}}
    table{{width:100%;border-collapse:collapse;margin-top:10px}}
    th,td{{padding:8px;border-bottom:1px solid #233366;text-align:left;vertical-align:top}}
    .pill{{display:inline-block;background:#0a1638;border:1px solid #24336a;border-radius:999px;padding:3px 8px;margin-right:6px}}
    a{{color:#9cc2ff}}
    .ok{{color:#55d38a}} .warn{{color:#e9c46a}} .bad{{color:#ef6f6c}}
  </style>
</head><body>
  <div class="wrap">
    <div class="card">
      <h1 id="title">Report</h1>
      <div id="meta"><small id="status">loading…</small></div>
      <div style="margin-top:8px">
        <span class="pill">Total pages: <strong id="total">0</strong></span>
        <span class="pill">Broken: <strong id="broken">0</strong></span>
        <span class="pill">Redirect issues: <strong id="redirects">0</strong></span>
        <span class="pill">Mixed content: <strong id="mixed">0</strong></span>
        <span class="pill">Large pages: <strong id="large">0</strong></span>
      </div>
      <div style="margin-top:8px">
        <a id="dlCsv" href="#">Download CSV (issues)</a> •
        <a id="dlJson" href="#">JSON</a>
      </div>
    </div>

    <div class="card" style="margin-top:14px">
      <h2 style="margin:0 0 8px">Pages</h2>
      <table id="pagesTbl">
        <thead><tr>
          <th>Title</th><th>URL</th><th>Status</th><th>Bytes</th><th>Time</th><th>Redirects</th>
        </tr></thead>
        <tbody id="pagesBody"><tr><td colspan="6">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>

<script>
(async function() {{
  const id = new URLSearchParams(location.search).get('id');
  const statusEl = document.getElementById('status');
  const totalEl = document.getElementById('total');
  const brokenEl = document.getElementById('broken');
  const redirectsEl = document.getElementById('redirects');
  const mixedEl = document.getElementById('mixed');
  const largeEl = document.getElementById('large');
  const bodyEl = document.getElementById('pagesBody');
  const titleEl = document.getElementById('title');

  if(!id) {{
    statusEl.textContent = 'Missing ?id=…';
    bodyEl.innerHTML = '<tr><td colspan="6">Missing report id.</td></tr>';
    return;
  }}

  const res = await fetch('/api/report?id=' + encodeURIComponent(id));
  const dataTxt = await res.text();
  let data; try {{ data = JSON.parse(dataTxt); }} catch {{ data = {{}}; }}
  if(!res.ok) {{
    statusEl.textContent = 'HTTP ' + res.status;
    bodyEl.innerHTML = '<tr><td colspan="6">Could not load report.</td></tr>';
    return;
  }}

  // Expected shape:
  // {{ url, status, created_at, pages: [{{title,url,status,bytes,time_ms|ms,redirects,mixed}}], issues_csv_url, json_url, large_threshold }}
  titleEl.textContent = 'Report';
  statusEl.textContent = (data.status || 'done') + ' — ' + (data.url || '');
  document.getElementById('dlCsv').href = data.issues_csv_url || ('/api/report.csv?id=' + encodeURIComponent(id));
  document.getElementById('dlJson').href = data.json_url || ('/api/report?id=' + encodeURIComponent(id));

  const pages = Array.isArray(data.pages) ? data.pages : [];
  const THRESH = Number(data.large_threshold || 2000000); // 2MB default

  // --- Compute counters from rows ---
  const total = pages.length;
  const broken = pages.filter(p => (Number(p.status)||0) === 0 || Number(p.status) >= 400).length;
  const redirs = pages.filter(p => Number(p.redirects||0) > 0).length;
  const mixed  = pages.filter(p => p.mixed === true).length;
  const large  = pages.filter(p => Number(p.bytes||0) > THRESH).length;

  totalEl.textContent = total;
  brokenEl.textContent = broken;
  redirectsEl.textContent = redirs;
  mixedEl.textContent = mixed;
  largeEl.textContent = large;

  // Render table
  if(!pages.length) {{
    bodyEl.innerHTML = '<tr><td colspan="6">No pages recorded.</td></tr>';
  }} else {{
    const rows = pages.map(p => {{
      const st = Number(p.status||0);
      const cls = st===0||st>=400 ? 'bad' : (st>=300&&st<400 ? 'warn' : 'ok');
      const ms = Number(p.time_ms || p.ms || 0);
      return `<tr>
        <td>${{String(p.title||'').replace(/</g,'&lt;')}}</td>
        <td><a href="${{p.url}}" target="_blank" rel="noopener">${{p.url}}</a></td>
        <td class="${{cls}}">${{st||0}}</td>
        <td>${{Number(p.bytes||0).toLocaleString()}}</td>
        <td>${{ms}} ms</td>
        <td>${{Number(p.redirects||0)}}</td>
      </tr>`;
    }}).join('');
    bodyEl.innerHTML = rows;
  }}
}})();
</script>
</body></html>
"""
    return HTMLResponse(html)
# === END LINKWATCH PATCH v0.2 ===

# ---------- Run local ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))

