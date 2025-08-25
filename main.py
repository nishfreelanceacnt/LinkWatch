import os, re, io, csv, time, json, asyncio, hashlib
from typing import Optional, List, Dict, Tuple, Set
from urllib.parse import urlparse, urljoin, urlunsplit

from fastapi import FastAPI, HTTPException, Query, Header, Request, Response, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response as FastAPIResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

import httpx
from bs4 import BeautifulSoup
import sqlite3
from datetime import datetime, timezone
import smtplib
from email.message import EmailMessage
import urllib.robotparser as robotparser

# -------------------- Config --------------------
APP_NAME = "LinkWatch"
APP_VER  = "0.9.0"

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
PLAUSIBLE_DOMAIN = os.getenv("PLAUSIBLE_DOMAIN", "").strip()
GOOGLE_SITE_VERIFICATION = os.getenv("GOOGLE_SITE_VERIFICATION","").strip()

CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS","*")
cors_origins = ["*"] if CORS_ALLOW_ORIGINS.strip()=="*" else [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]

DB_PATH = os.getenv("LW_DB_PATH","linkwatch.db")

SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY","8"))
SCAN_TIMEOUT_SEC = float(os.getenv("SCAN_TIMEOUT_SECONDS","10"))
SCAN_MAX_PAGES_FREE = int(os.getenv("SCAN_MAX_PAGES_FREE","150"))
SCAN_MAX_PAGES_HARD = int(os.getenv("SCAN_MAX_PAGES_HARD","5000"))
SCAN_RESPECT_ROBOTS = os.getenv("SCAN_RESPECT_ROBOTS","1").lower() in ("1","true","yes","on")
USER_AGENT = os.getenv("LW_USER_AGENT", f"{APP_NAME}/{APP_VER} (+https://example.com)")

RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN","10"))

SMTP_HOST = os.getenv("SMTP_HOST","")
SMTP_PORT = int(os.getenv("SMTP_PORT","587"))
SMTP_USER = os.getenv("SMTP_USER","")
SMTP_PASS = os.getenv("SMTP_PASS","")
REPORT_EMAIL_FROM = os.getenv("REPORT_EMAIL_FROM", SMTP_USER)

# -------------------- App --------------------
app = FastAPI(
    title=APP_NAME,
    version=APP_VER,
    openapi_tags=[
        {"name":"Scan", "description":"Start scans, fetch status and results"},
        {"name":"Reports", "description":"Shareable reports and exports"},
        {"name":"Pages", "description":"Public pages (Home, FAQ)"},
        {"name":"SEO", "description":"Robots & sitemap"},
    ],
)
app.add_middleware(GZipMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=cors_origins, allow_methods=["*"], allow_headers=["*"])

# Security headers
class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        return resp
app.add_middleware(SecurityHeaders)

# -------------------- Analytics / Meta --------------------
def _analytics_snippet() -> str:
    if not PLAUSIBLE_DOMAIN: return ""
    return '<script defer data-domain="'+PLAUSIBLE_DOMAIN+'" src="https://plausible.io/js/script.js"></script>'

def _google_verify_snippet() -> str:
    if not GOOGLE_SITE_VERIFICATION: return ""
    return '<meta name="google-site-verification" content="'+GOOGLE_SITE_VERIFICATION+'"/>'

def _html_head(title: str) -> str:
    return (
        '<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>'
        + _google_verify_snippet()
        + "<title>"+title+"</title><link rel=\"icon\" href=\"/favicon.svg\">"
        + _analytics_snippet()
        + """
<style>
:root{--bg:#0b1020;--card:#121933;--muted:#8da2d0;--text:#eef2ff;--accent:#6ea8fe;--ok:#55d38a;--warn:#e9c46a;--bad:#ef6f6c}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto}
.wrap{max-width:980px;margin:40px auto;padding:0 16px}
.card{background:var(--card);border-radius:16px;padding:22px;box-shadow:0 4px 24px rgba(0,0,0,.25)}
h1{margin:0 0 8px;font-size:28px} h2{margin:0 0 8px} p{margin:0 0 12px;color:var(--muted)}
header{display:flex;align-items:center;gap:12px;margin-bottom:14px}
header img{width:36px;height:36px}
nav a{color:#9cc2ff;margin-right:14px;text-decoration:none} nav a:hover{text-decoration:underline}
label{display:block;margin:12px 0 6px;color:#c8d1f5}
input,button,select{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:var(--text)}
button{background:var(--accent);border:none;color:#04122d;font-weight:700;cursor:pointer}
small{color:var(--muted)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid{display:grid;gap:12px} @media(min-width:860px){.grid{grid-template-columns:1.4fr 1fr}}
pre{background:#0a0f24;border:1px solid #26335f;border-radius:12px;padding:14px;overflow:auto}
table{width:100%;border-collapse:collapse}
th,td{padding:8px;border-bottom:1px solid #233366;text-align:left;vertical-align:top}
.bad{color:var(--bad)} .ok{color:var(--ok)} .warn{color:var(--warn)}
.kpi{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.kpi .box{background:#0e1630;border:1px solid #233366;border-radius:12px;padding:10px}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #233366;background:#0e1630;margin-right:6px}
.btn{display:inline-block;padding:8px 12px;border-radius:8px;border:1px solid #233366;background:#0e1630;color:#eaf0ff;text-decoration:none}
.hint{font-size:13px;color:#aab8e6}
progress{width:100%}
</style>
"""
    )

# -------------------- Logo / favicon --------------------
LOGO_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'>
  <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#6ea8fe'/><stop offset='100%' stop-color='#7bd3ff'/></linearGradient></defs>
  <rect x='16' y='16' width='224' height='224' rx='48' fill='#0e1630'/>
  <rect x='24' y='24' width='208' height='208' rx='40' fill='url(#g)' opacity='0.08'/>
  <g fill='#eaf0ff'>
    <path d='M74 74h108v24H74zM74 110h108v24H74zM74 146h108v24H74z' opacity='.9'/>
    <circle cx='200' cy='200' r='28' fill='#6ea8fe'/>
    <path d='M198 186h4v28h-4zM186 198h28v4h-28z' fill='#0e1630'/>
  </g>
</svg>"""

@app.get("/favicon.svg")
def favicon_svg(): return FastAPIResponse(content=LOGO_SVG, media_type="image/svg+xml")

@app.get("/logo.svg")
def logo_svg(): return FastAPIResponse(content=LOGO_SVG, media_type="image/svg+xml")

# -------------------- Rate limit --------------------
_rl: Dict[str, List[float]] = {}
def rate_limit_ok(bucket: str) -> bool:
    now = time.time(); window = 60.0; lim = RATE_LIMIT_PER_MIN
    arr = [t for t in _rl.get(bucket, []) if now - t < window]
    if len(arr) >= lim: _rl[bucket] = arr; return False
    arr.append(now); _rl[bucket] = arr; return True

def rl_or_429(request: Request):
    ident = request.client.host if request.client else "unknown"
    if not rate_limit_ok(ident):
        raise HTTPException(status_code=429, detail="Too many requests. Please slow down.")

# -------------------- DB --------------------
def db_conn():
    return sqlite3.connect(DB_PATH)

def db_init():
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("""
          CREATE TABLE IF NOT EXISTS scans(
            id TEXT PRIMARY KEY,
            site_url TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            total_pages INTEGER DEFAULT 0,
            broken_links INTEGER DEFAULT 0,
            redirect_issues INTEGER DEFAULT 0,
            mixed_content INTEGER DEFAULT 0,
            large_pages INTEGER DEFAULT 0,
            email TEXT
          )
        """)
        cur.execute("""
          CREATE TABLE IF NOT EXISTS pages(
            scan_id TEXT,
            url TEXT,
            status INTEGER,
            content_type TEXT,
            bytes INTEGER,
            ms INTEGER,
            title TEXT,
            redirects INTEGER,
            PRIMARY KEY(scan_id, url)
          )
        """)
        cur.execute("""
          CREATE TABLE IF NOT EXISTS issues(
            scan_id TEXT,
            from_url TEXT,
            to_url TEXT,
            status INTEGER,
            redirects INTEGER,
            type TEXT,
            mixed_http INTEGER DEFAULT 0,
            note TEXT
          )
        """)
        con.commit()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# -------------------- Helpers --------------------
_abs_bad = ("mailto:", "tel:", "javascript:", "data:")
def is_http_url(u: str) -> bool:
    return u.startswith("http://") or u.startswith("https://")

def same_host(u: str, root: str) -> bool:
    try:
        return urlparse(u).netloc == urlparse(root).netloc
    except Exception:
        return False

def normalize_url(base: str, href: str) -> Optional[str]:
    if not href: return None
    href = href.strip()
    if any(href.lower().startswith(p) for p in _abs_bad): return None
    try:
        return urljoin(base, href)
    except Exception:
        return None

def sha(x: str) -> str:
    return hashlib.sha1(x.encode("utf-8")).hexdigest()[:10]

# -------------------- Crawler --------------------
class ScanTask:
    def __init__(self, scan_id: str, site_url: str, max_pages: int, respect_robots: bool, email: Optional[str]):
        self.scan_id = scan_id
        self.site_url = site_url
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.email = email

        self.total_pages = 0
        self.broken_links = 0
        self.redirect_issues = 0
        self.mixed_content = 0
        self.large_pages = 0

        self.done = False
        self.error: Optional[str] = None
        self.progress_pages = 0

_tasks: Dict[str, ScanTask] = {}

async def fetch_one(client: httpx.AsyncClient, url: str) -> Tuple[int, Dict]:
    t0 = time.perf_counter()
    try:
        r = await client.get(url, follow_redirects=True)
        ms = int((time.perf_counter()-t0)*1000)
        ct = r.headers.get("content-type","").split(";")[0].strip().lower()
        title = ""
        if (ct.startswith("text/html") or ct == "") and r.text:
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()[:300]
            except Exception:
                pass
        redirects = len(getattr(r, "history", []) or [])
        data = {"status": r.status_code, "content_type": ct, "bytes": len(r.content), "ms": ms, "title": title, "redirects": redirects, "text": r.text if ct.startswith("text/html") else ""}
        return r.status_code, data
    except Exception:
        ms = int((time.perf_counter()-t0)*1000)
        return 0, {"status": 0, "content_type": "", "bytes": 0, "ms": ms, "title": "", "redirects": 0, "text": ""}

def extract_links(base_url: str, html_text: str) -> List[Tuple[str,str]]:
    out: List[Tuple[str,str]] = []
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        for a in soup.select("a[href]"):
            u = normalize_url(base_url, a.get("href"))
            if u: out.append(("a", u))
        for im in soup.select("img[src]"):
            u = normalize_url(base_url, im.get("src"))
            if u: out.append(("img", u))
        for sc in soup.select("script[src]"):
            u = normalize_url(base_url, sc.get("src"))
            if u: out.append(("script", u))
        for lk in soup.select("link[href]"):
            u = normalize_url(base_url, lk.get("href"))
            if u: out.append(("link", u))
    except Exception:
        pass
    return out

async def run_scan(task: ScanTask):
    _tasks[task.scan_id] = task
    # init DB row
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("INSERT OR REPLACE INTO scans(id, site_url, status, created_at, started_at, email) VALUES (?,?,?,?,?,?)",
                    (task.scan_id, task.site_url, "running", now_iso(), now_iso(), task.email))
        con.commit()

    rootscheme = urlparse(task.site_url).scheme
    rp = None
    if task.respect_robots:
        try:
            robots_url = urljoin(task.site_url, "/robots.txt")
            rp = robotparser.RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
        except Exception:
            rp = None

    limits = httpx.Limits(max_keepalive_connections=SCAN_CONCURRENCY, max_connections=SCAN_CONCURRENCY)
    headers = {"User-Agent": USER_AGENT, "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    timeout = httpx.Timeout(SCAN_TIMEOUT_SEC, connect=SCAN_TIMEOUT_SEC)
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    visited_pages: Set[str] = set()
    to_visit: asyncio.Queue[str] = asyncio.Queue()
    await to_visit.put(task.site_url)

    checked_links: Set[str] = set()

    async with httpx.AsyncClient(limits=limits, headers=headers, timeout=timeout) as client:
        while not to_visit.empty() and task.total_pages < task.max_pages:
            page_url = await to_visit.get()
            if page_url in visited_pages:
                continue
            if not is_http_url(page_url):
                continue
            if same_host(page_url, task.site_url) is False:
                continue
            if rp and not rp.can_fetch(USER_AGENT, page_url):
                continue

            visited_pages.add(page_url)
            task.progress_pages = len(visited_links_or_pages(visited_pages))
            async with sem:
                status, meta = await fetch_one(client, page_url)

            # store page
            with db_conn() as con:
                cur = con.cursor()
                cur.execute("INSERT OR REPLACE INTO pages(scan_id,url,status,content_type,bytes,ms,title,redirects) VALUES (?,?,?,?,?,?,?,?)",
                            (task.scan_id, page_url, meta["status"], meta["content_type"], meta["bytes"], meta["ms"], meta["title"], meta["redirects"]))
                con.commit()

            task.total_pages += 1
            if meta["bytes"] > 2_000_000: task.large_pages += 1

            # Extract + check links
            links = extract_links(page_url, meta.get("text",""))
            # Mixed content check
            page_https = page_url.startswith("https://")
            to_check_unique: List[Tuple[str,str]] = []
            for ltype, href in links:
                # Mixed content?
                mixed = 1 if (page_https and href.startswith("http://")) else 0
                if mixed:
                    task.mixed_content += 1
                    with db_conn() as con:
                        cur = con.cursor()
                        cur.execute("INSERT INTO issues(scan_id,from_url,to_url,status,redirects,type,mixed_http,note) VALUES (?,?,?,?,?,?,?,?)",
                                    (task.scan_id, page_url, href, None, None, ltype, 1, "Mixed content on HTTPS page"))
                        con.commit()
                # We won't crawl external pages, but we will check their status once
                if href not in checked_links and is_http_url(href):
                    checked_links.add(href)
                    to_check_unique.append((ltype, href))

            # Check link statuses in small batches
            async def check_link(ltype: str, target: str):
                try:
                    async with sem:
                        r = await client.get(target, follow_redirects=True)
                    st = r.status_code
                    redirects = len(r.history or [])
                except Exception:
                    st = 0; redirects = 0
                note = None
                if st >= 400 or st == 0:
                    task.broken_links += 1
                    note = "Broken link"
                elif redirects > 1:
                    task.redirect_issues += 1
                    note = "Long redirect chain"
                if note:
                    with db_conn() as con:
                        cur = con.cursor()
                        cur.execute("INSERT INTO issues(scan_id,from_url,to_url,status,redirects,type,mixed_http,note) VALUES (?,?,?,?,?,?,?,?)",
                                    (task.scan_id, page_url, target, st, redirects, ltype, 0, note))
                        con.commit()

            # run in parallel but gently
            await asyncio.gather(*[check_link(t, u) for (t,u) in to_check_unique[:200]])  # cap per page

            # enqueue same-host HTML pages (best guess: only enqueue links from anchor/link rel=)
            for ltype, href in links:
                if ltype != "a": continue
                if same_host(href, task.site_url) and href not in visited_pages and to_visit.qsize() < task.max_pages*2:
                    await to_visit.put(href)

    # finalize scan row
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("""UPDATE scans SET status=?, finished_at=?, total_pages=?, broken_links=?, redirect_issues=?, mixed_content=?, large_pages=?
                       WHERE id=?""",
                    ("done", now_iso(), task.total_pages, task.broken_links, task.redirect_issues, task.mixed_content, task.large_pages, task.scan_id))
        con.commit()

    task.done = True

    # optional email
    if SMTP_HOST and REPORT_EMAIL_FROM and task.email:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[{APP_NAME}] Report ready for {task.site_url}"
            msg["From"] = REPORT_EMAIL_FROM
            msg["To"] = task.email
            base = PUBLIC_BASE_URL or ""
            msg.set_content(
                "Your LinkWatch report is ready.\n\n"
                f"{base}/report/{task.scan_id}\n\n"
                "Thanks for using LinkWatch!"
            )
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
                s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.send_message(msg)
        except Exception:
            pass

def visited_links_or_pages(s: Set[str]) -> Set[str]:
    return s

# -------------------- Pages --------------------
HOME_HTML = (
    "<!doctype html><html lang='en'><head>"
    + _html_head(APP_NAME+" — Broken Link & Redirect Scanner")
    + "</head><body><div class='wrap'>"
    + "<header><img src='/logo.svg' alt='logo'/><strong>"+APP_NAME+"</strong></header>"
    + "<nav><a href='/'>Home</a><a href='/faq'>FAQ</a><a href='/docs'>Docs</a></nav>"
    + "<div class='card'><h1>Scan your site for broken links</h1>"
    + "<p>Paste your website URL. We’ll crawl your domain, flag broken links (4xx/5xx), long redirect chains, mixed content, and large pages.</p>"
    + "<form method='post' action='/scan/start'>"
    + "<label>Website URL</label><input name='site_url' placeholder='https://yoursite.com' required/>"
    + "<div class='row'><div><label>Max pages</label><input name='max_pages' type='number' value='"+str(SCAN_MAX_PAGES_FREE)+"'/></div>"
    + "<div><label>Respect robots.txt</label><select name='respect_robots'><option value='1'"+(" selected" if SCAN_RESPECT_ROBOTS else "")+">Yes</option><option value='0'>No</option></select></div></div>"
    + "<label class='hint'>Optional: Email (we’ll send a link when it’s ready)</label><input name='email' type='email' placeholder='you@domain.com'/>"
    + "<div style='margin-top:10px'><button type='submit'>Start Scan</button></div>"
    + "<small class='hint'>Free scans up to "+str(SCAN_MAX_PAGES_FREE)+" pages. Larger sites? Reduce max pages or run multiple sections.</small>"
    + "</form></div>"
    + "<div class='card' style='margin-top:14px'><h2>How it works</h2>"
    + "<ul><li>We crawl same-domain links up to your page limit.</li>"
    + "<li>We test unique links (internal and external) for broken status and redirect chains.</li>"
    + "<li>We flag mixed content on HTTPS pages and very large pages.</li></ul></div>"
    + "</div><script>/* minimal */</script></body></html>"
)

FAQ_HTML = (
    "<!doctype html><html lang='en'><head>"+_html_head(APP_NAME+" — FAQ")+"</head><body><div class='wrap'>"
    + "<header><img src='/logo.svg' alt='logo'/><strong>"+APP_NAME+"</strong></header>"
    + "<nav><a href='/'>Home</a><a href='/faq'>FAQ</a><a href='/docs'>Docs</a></nav>"
    + "<div class='card'><h1>FAQ</h1>"
    + "<h3>What limits apply?</h3><p>Free scans default to "+str(SCAN_MAX_PAGES_FREE)+" pages per run, with timeouts and concurrency to be polite.</p>"
    + "<h3>Do you follow robots.txt?</h3><p>"+("Yes, by default. You can disable it per scan." if SCAN_RESPECT_ROBOTS else "No, you can enable it in the form.")+"</p>"
    + "<h3>What do you store?</h3><p>We store scan metadata, page metrics, and issues for your shareable report.</p>"
    + "<h3>How do I export?</h3><p>On the report page, download CSV or JSON.</p>"
    + "</div></div></body></html>"
)

@app.get("/", response_class=HTMLResponse, tags=["Pages"])
def home(): return HTMLResponse(HOME_HTML)

@app.get("/faq", response_class=HTMLResponse, tags=["Pages"])
def faq(): return HTMLResponse(FAQ_HTML)

# -------------------- SEO: robots/sitemap --------------------
@app.get("/robots.txt", response_class=PlainTextResponse, tags=["SEO"])
def robots(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    return PlainTextResponse("User-agent: *\nAllow: /\nSitemap: "+base+"/sitemap.xml\n")

@app.get("/sitemap.xml", tags=["SEO"])
def sitemap(request: Request):
    base = PUBLIC_BASE_URL or urlunsplit((request.url.scheme, request.url.netloc, "", "", ""))
    urls = ["/", "/faq"]
    items = "".join("<url><loc>"+base+p+"</loc></url>" for p in urls)
    xml = "<?xml version='1.0' encoding='UTF-8'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"+items+"</urlset>"
    return FastAPIResponse(content=xml, media_type="application/xml")

@app.get("/docs", include_in_schema=False)
def docs_redirect(): return RedirectResponse(url="/docs/swagger")

# -------------------- Scan endpoints --------------------
def validate_site_url(u: str):
    try:
        p = urlparse(u)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL")
    if p.scheme not in ("http","https"): raise HTTPException(status_code=400, detail="URL must be http or https")
    if not p.netloc: raise HTTPException(status_code=400, detail="URL missing host")

@app.post("/scan/start", tags=["Scan"])
async def start_scan(request: Request,
    site_url: str = Form(...),
    max_pages: int = Form(SCAN_MAX_PAGES_FREE),
    respect_robots: int = Form(1),
    email: Optional[str] = Form(None)
):
    rl_or_429(request)
    site_url = site_url.strip()
    validate_site_url(site_url)
    m = max(1, min(int(max_pages), SCAN_MAX_PAGES_HARD))
    if m > SCAN_MAX_PAGES_FREE:
        m = SCAN_MAX_PAGES_FREE  # free tier cap for now
    sid = sha(site_url + "|" + str(time.time()))
    t = ScanTask(sid, site_url, m, bool(int(respect_robots)), email.strip() if email else None)
    _tasks[sid] = t
    # create scan row
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("INSERT OR REPLACE INTO scans(id, site_url, status, created_at, email) VALUES (?,?,?,?,?)",
                    (sid, site_url, "queued", now_iso(), t.email))
        con.commit()

    # kick off the task
    asyncio.create_task(run_scan(t))
    # redirect to report which will poll status
    return RedirectResponse(url="/report/"+sid, status_code=303)

@app.get("/scan/status/{scan_id}", tags=["Scan"])
def scan_status(scan_id: str):
    t = _tasks.get(scan_id)
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("SELECT status,total_pages,broken_links,redirect_issues,mixed_content,large_pages,created_at,started_at,finished_at,site_url FROM scans WHERE id=?",(scan_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")
        status, total, broken, redir, mixed, large, created_at, started_at, finished_at, site_url = row
    prog = t.progress_pages if t else total
    return {
        "scan_id": scan_id,
        "site_url": site_url,
        "status": status if (status!="running" or not t or not t.done) else "running",
        "progress_pages": prog,
        "total_pages": total,
        "metrics": {
            "broken_links": broken, "redirect_issues": redir, "mixed_content": mixed, "large_pages": large
        },
        "timestamps": {"created_at": created_at, "started_at": started_at, "finished_at": finished_at}
    }

# -------------------- Reports & exports --------------------
def render_report_html(scan_id: str) -> str:
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("SELECT site_url,status,total_pages,broken_links,redirect_issues,mixed_content,large_pages,created_at,started_at,finished_at FROM scans WHERE id=?",(scan_id,))
        srow = cur.fetchone()
        if not srow: return "<h1>Not found</h1>"
        site_url, status, total, broken, redir, mixed, large, created_at, started_at, finished_at = srow
        cur.execute("SELECT url,status,bytes,ms,title,redirects FROM pages WHERE scan_id=? ORDER BY url LIMIT 5000",(scan_id,))
        pages = cur.fetchall()
        cur.execute("SELECT from_url,to_url,status,redirects,type,mixed_http,note FROM issues WHERE scan_id=? LIMIT 10000",(scan_id,))
        issues = cur.fetchall()

    badge = "<span class='tag'>"+status+"</span><span class='tag'>"+str(total)+" pages</span><span class='tag bad'>"+str(broken)+" broken</span><span class='tag warn'>"+str(redir)+" redirects</span><span class='tag warn'>"+str(mixed)+" mixed</span><span class='tag'>"+str(large)+" large</span>"

    # tables
    page_rows = "\n".join(
        "<tr><td>"+(title or "")+"</td><td><a href='"+u+"' target='_blank' rel='nofollow'>"+u+"</a></td><td>"+str(st)+"</td><td>"+str(b)+"</td><td>"+str(ms)+" ms</td><td>"+str(r)+"</td></tr>"
        for (u_stuff) in pages
        for u, st, b, ms, title, r in [u_stuff]
    ) or "<tr><td colspan='6'><em>No pages recorded.</em></td></tr>"

    issue_rows = "\n".join(
        "<tr><td>"+(note or "")+"</td><td>"+t+"</td><td><a href='"+fu+"' target='_blank' rel='nofollow'>"+fu+"</a></td>"
        "<td><a href='"+tu+"' target='_blank' rel='nofollow'>"+tu+"</a></td><td>"+(str(st) if st is not None else "")+"</td><td>"+str(r)+"</td><td>"+("yes" if mx else "no")+"</td></tr>"
        for (fu,tu,st,r,t,mx,note) in issues
    ) or "<tr><td colspan='7'><em>No issues detected.</em></td></tr>"

    base = PUBLIC_BASE_URL or ""
    head = _html_head(APP_NAME+" — Report")
    html = (
        "<!doctype html><html><head>"+head+"</head><body><div class='wrap'>"
        "<header><img src='/logo.svg' alt='logo'/><strong>"+APP_NAME+"</strong></header>"
        "<nav><a href='/'>Home</a><a href='/faq'>FAQ</a><a href='/docs'>Docs</a></nav>"
        "<div class='card'><h1>Report</h1>"
        "<p class='hint'>"+site_url+"</p>"
        "<div style='margin:8px 0'>"+badge+"</div>"
        "<div class='kpi'>"
        "<div class='box'><div>Total pages</div><div style='font-size:22px'>"+str(total)+"</div></div>"
        "<div class='box'><div class='bad'>Broken links</div><div style='font-size:22px'>"+str(broken)+"</div></div>"
        "<div class='box'><div class='warn'>Redirect issues</div><div style='font-size:22px'>"+str(redir)+"</div></div>"
        "<div class='box'><div>Mixed content</div><div style='font-size:22px'>"+str(mixed)+"</div></div>"
        "</div>"
        "<div style='margin-top:10px'>"
        "<a class='btn' href='/api/report/"+scan_id+".csv'>Download CSV (issues)</a> "
        "<a class='btn' href='/api/report/"+scan_id+".json' target='_blank'>JSON</a>"
        "</div>"
        "</div>"
        "<div class='card' style='margin-top:14px'><h2>Issues</h2>"
        "<table><thead><tr><th>Type</th><th>Tag</th><th>From</th><th>To</th><th>Status</th><th>Redirects</th><th>Mixed?</th></tr></thead><tbody>"
        + issue_rows + "</tbody></table></div>"
        "<div class='card' style='margin-top:14px'><h2>Pages</h2>"
        "<table><thead><tr><th>Title</th><th>URL</th><th>Status</th><th>Bytes</th><th>Time</th><th>Redirects</th></tr></thead><tbody>"
        + page_rows + "</tbody></table></div>"
        "<p class='hint' style='margin-top:10px'>Tip: Use the CSV to fix broken links in batches.</p>"
        "</div>"
        "<script>/* Poll status until done */"
        "async function poll(){try{const r=await fetch('/scan/status/"+scan_id+"'); const j=await r.json(); if(j.status!=='done'){setTimeout(poll,1500);} }catch(e){}} poll();"
        "</script></body></html>"
    )
    return html

@app.get("/report/{scan_id}", response_class=HTMLResponse, tags=["Reports"])
def report_page(scan_id: str):
    html = render_report_html(scan_id)
    return HTMLResponse(html)

@app.get("/api/report/{scan_id}.json", tags=["Reports"])
def report_json(scan_id: str):
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("SELECT site_url,status,total_pages,broken_links,redirect_issues,mixed_content,large_pages,created_at,started_at,finished_at FROM scans WHERE id=?",(scan_id,))
        srow = cur.fetchone()
        if not srow: raise HTTPException(status_code=404, detail="Scan not found")
        site_url, status, total, broken, redir, mixed, large, created_at, started_at, finished_at = srow
        cur.execute("SELECT url,status,bytes,ms,title,redirects FROM pages WHERE scan_id=?",(scan_id,))
        pages = cur.fetchall()
        cur.execute("SELECT from_url,to_url,status,redirects,type,mixed_http,note FROM issues WHERE scan_id=?",(scan_id,))
        issues = cur.fetchall()
    return {
        "scan_id": scan_id,
        "site_url": site_url,
        "status": status,
        "summary": {
            "total_pages": total, "broken_links": broken, "redirect_issues": redir, "mixed_content": mixed, "large_pages": large
        },
        "pages": [
            {"url":u, "status":st, "bytes":b, "ms":ms, "title":title, "redirects":r} for (u,st,b,ms,title,r) in pages
        ],
        "issues": [
            {"from":fu, "to":tu, "status":st, "redirects":r, "type":t, "mixed":bool(mx), "note":note} for (fu,tu,st,r,t,mx,note) in issues
        ],
        "timestamps": {"created_at": created_at, "started_at": started_at, "finished_at": finished_at},
    }

@app.get("/api/report/{scan_id}.csv", response_class=PlainTextResponse, tags=["Reports"])
def report_csv(scan_id: str):
    with db_conn() as con:
        cur = con.cursor()
        cur.execute("SELECT from_url,to_url,status,redirects,type,mixed_http,note FROM issues WHERE scan_id=?",(scan_id,))
        issues = cur.fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type","from_url","to_url","status","redirects","mixed_http","note"])
    for (fu,tu,st,r,t,mx,note) in issues:
        w.writerow([t, fu, tu, st, r, mx, note])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")

# -------------------- Health --------------------
@app.get("/healthz")
def healthz(): return {"ok": True, "version": APP_VER}

# -------------------- Startup --------------------
@app.on_event("startup")
def _startup():
    db_init()

# -------------------- Local run --------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT","8000")), reload=True)
