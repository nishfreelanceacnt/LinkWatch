import os, re, time, json, csv, io, asyncio, hashlib, datetime
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from fastapi import FastAPI, Request, Form, HTTPException, Query
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    StreamingResponse,
    Response as FastAPIResponse,
    PlainTextResponse,
    RedirectResponse,
)

# ----- DB (Postgres or SQLite) -----
import sqlite3
try:
    import psycopg2
    HAS_PG = True
except Exception:
    HAS_PG = False

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_IS_PG = bool(DATABASE_URL and DATABASE_URL.startswith("postgres"))

def db_conn():
    if DB_IS_PG:
        if not HAS_PG:
            raise RuntimeError("psycopg2 required for Postgres")
        return psycopg2.connect(DATABASE_URL)
    else:
        return sqlite3.connect("linkwatch.db")

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
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    report_data JSONB,
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
                    url TEXT NOT NULL,
                    status_code INT,
                    checked_at TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    report_data TEXT,
                    created_at TEXT
                )
            """)
            con.commit()

# ----- App -----
app = FastAPI(title="LinkWatch", version="0.2.0")
app.add_middleware(GZipMiddleware)

CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")
cors_origins = ["*"] if CORS_ALLOW_ORIGINS.strip() == "*" else [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Security headers (minimal & safe for embed) ----
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return resp

# ----- Progress (in-memory; resets on restarts) -----
PROGRESS: Dict[str, Dict] = {}  # task_id -> status blob

# ----- Helpers -----
USER_AGENT = "LinkWatchBot/0.2 (+https://example.com)"
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "12.0"))
MAX_PAGES = int(os.getenv("MAX_PAGES", "120"))
MAX_DEPTH = int(os.getenv("MAX_DEPTH", "3"))
MAX_BYTES_PAGE = int(os.getenv("MAX_BYTES_PAGE", "2500000"))  # 2.5MB

def same_host(u1: str, u2: str) -> bool:
    try:
        return urlparse(u1).netloc == urlparse(u2).netloc
    except Exception:
        return False

def normalize_url(base: str, href: str) -> Optional[str]:
    if not href:
        return None
    u = urljoin(base, href)
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        return None
    # strip fragments
    return u.split("#", 1)[0]

def fetch_url(u: str) -> Tuple[int, bytes, str, int, int]:
    """
    Returns: (status_code, content_bytes, final_url, redirects_count, content_length_reported)
    """
    try:
        r = requests.get(u, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT, allow_redirects=True)
        status = r.status_code
        final_url = str(r.url)
        redirs = len(r.history or [])
        content = r.content or b""
        cl = 0
        try:
            cl = int(r.headers.get("Content-Length", "0"))
        except Exception:
            cl = 0
        return status, content, final_url, redirs, cl
    except requests.RequestException:
        return 599, b"", u, 0, 0

def detect_mixed_content(page_url: str, html: str) -> bool:
    # if the page is https and references http images/scripts/links, flag it.
    if not page_url.lower().startswith("https://"):
        return False
    if "http://" in html:
        # quick & coarse: any http:// on an https page considered mixed
        return True
    return False

def html_title(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "html.parser")
        t = soup.find("title")
        return (t.get_text(strip=True) if t else "")[:140]
    except Exception:
        return ""

# ----- Crawl job -----
def run_crawl_job(task_id: str, start_url: str, email: Optional[str]):
    try:
        PROGRESS[task_id] = {"status": "running", "progress": 0, "total": 100, "report_id": None, "message": "Queueing"}

        start = start_url.strip()
        seen = set()
        queue = [(start, 0)]
        pages = []
        issues = []

        host = urlparse(start).netloc
        total_budget = MAX_PAGES
        last_emit = 0

        steps_est = max(20, min(100, total_budget))
        def emit(pct: int, msg: str):
            now = time.time()
            nonlocal last_emit
            if now - last_emit > 0.15 or pct >= 100:
                PROGRESS[task_id]["progress"] = pct
                PROGRESS[task_id]["message"] = msg
                last_emit = now

        count = 0
        while queue and count < total_budget:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            count += 1

            status, body, final_url, redirects, cl = fetch_url(url)
            txt = ""
            try:
                if len(body) > MAX_BYTES_PAGE:
                    # too large to parse safely
                    txt = ""
                else:
                    txt = body.decode("utf-8", errors="replace")
            except Exception:
                txt = ""

            # page record
            page_title = html_title(txt) if txt else ""
            pages.append({
                "url": url,
                "final_url": final_url,
                "status": status,
                "bytes": len(body),
                "redirects": redirects,
                "title": page_title,
                "time_ms": 0,   # (optional: track timing)
                "mixed": bool(detect_mixed_content(final_url, txt)) if txt else False,
            })

            # issues
            if status >= 400 or status == 0:
                issues.append({
                    "type": "broken",
                    "tag": "a",
                    "from": url,
                    "to": final_url,
                    "status": status,
                    "redirects": redirects,
                    "mixed": False,
                })
            elif redirects >= 2:
                issues.append({
                    "type": "redirect",
                    "tag": "a",
                    "from": url,
                    "to": final_url,
                    "status": status,
                    "redirects": redirects,
                    "mixed": False,
                })
            if len(body) > MAX_BYTES_PAGE:
                issues.append({
                    "type": "large",
                    "tag": "page",
                    "from": url,
                    "to": final_url,
                    "status": status,
                    "redirects": redirects,
                    "mixed": False,
                })
            if txt and detect_mixed_content(final_url, txt):
                issues.append({
                    "type": "mixed",
                    "tag": "page",
                    "from": url,
                    "to": final_url,
                    "status": status,
                    "redirects": redirects,
                    "mixed": True,
                })

            # discovery
            if txt and depth < MAX_DEPTH and same_host(start, final_url):
                try:
                    soup = BeautifulSoup(txt, "html.parser")
                    for a in soup.find_all("a", href=True):
                        nu = normalize_url(final_url, a.get("href", ""))
                        if nu and same_host(start, nu) and nu not in seen:
                            queue.append((nu, depth + 1))
                except Exception:
                    pass

            pct = int(min(100, (count / total_budget) * 100))
            emit(pct, f"Scanning… {pct}%")

        # Build summary
        summary = {
            "scanned": len(pages),
            "broken": sum(1 for it in issues if it.get("type") == "broken"),
            "redirects": sum(1 for it in issues if it.get("type") == "redirect"),
            "mixed": sum(1 for it in issues if it.get("type") == "mixed"),
            "large": sum(1 for it in issues if it.get("type") == "large"),
            "start_url": start_url,
            "host": host,
        }

        report = {"summary": summary, "pages": pages, "issues": issues}

        # Persist
        with db_conn() as con:
            cur = con.cursor()
            now = datetime.datetime.utcnow().isoformat() + "Z"
            if DB_IS_PG:
                q = "INSERT INTO reports(email, report_data) VALUES (%s, %s) RETURNING id"
                cur.execute(q, (email or "", json.dumps(report)))
                rid = cur.fetchone()[0]
            else:
                q = "INSERT INTO reports(email, report_data, created_at) VALUES (?, ?, ?)"
                cur.execute(q, (email or "", json.dumps(report), now))
                rid = cur.lastrowid
            con.commit()

        PROGRESS[task_id]["status"] = "done"
        PROGRESS[task_id]["progress"] = 100
        PROGRESS[task_id]["report_id"] = rid
        PROGRESS[task_id]["message"] = "Completed"
    except Exception as e:
        PROGRESS[task_id]["status"] = "error"
        PROGRESS[task_id]["message"] = str(e)

# ----- Pages -----
def _head(title: str) -> str:
    return f"""
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title}</title>
<link rel="icon" href="/favicon.svg"/>
<style>
:root{{--bg:#0b1020;--card:#121933;--muted:#8da2d0;--text:#eef2ff;--accent:#7dd3fc}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto}}
.wrap{{max-width:960px;margin:36px auto;padding:0 16px}}
.card{{background:var(--card);border-radius:16px;padding:22px;box-shadow:0 4px 24px rgba(0,0,0,.25)}}
h1{{margin:0 0 6px}} p{{margin:0 0 12px;color:var(--muted)}}
label{{display:block;margin:12px 0 6px;color:#cbd6ff}}
input,button{{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:var(--text)}}
button{{background:var(--accent);border:none;color:#04122d;font-weight:800;cursor:pointer}}
.row{{display:grid;grid-template-columns:2fr 1fr;gap:12px}}
.btn{{display:inline-block;padding:8px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:#eaf0ff;text-decoration:none}}
small{{color:var(--muted)}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:8px;border-bottom:1px solid #233366;text-align:left}}
pre{{background:#0a0f24;border:1px solid #26335f;border-radius:12px;padding:12px;overflow:auto}}
</style>
"""

HOME_HTML = f"""<!doctype html><html><head>{_head("LinkWatch — Broken Links & Issues Scanner")}</head>
<body><div class="wrap">
  <div class="card">
    <h1>LinkWatch</h1>
    <p>Scan a site for broken links, heavy pages, and mixed content. (Free tier limits apply.)</p>
    <div class="row">
      <input id="url" placeholder="https://your-site.com/"/>
      <button id="start" type="button">Start Scan</button>
    </div>
    <div style="margin-top:10px;background:#0a0f24;border:1px solid #26335f;border-radius:12px;overflow:hidden;height:16px">
      <div id="bar" style="height:100%;width:0%;background:#55d38a"></div>
    </div>
    <div id="label" style="margin-top:6px"><small>Waiting…</small></div>
    <div style="margin-top:10px">
      <a id="dl-json" class="btn" href="#" onclick="return false;" aria-disabled="true">Download JSON</a>
      <a id="dl-csv"  class="btn" href="#" onclick="return false;" aria-disabled="true" style="margin-left:8px">Download CSV</a>
      <span id="open-report" style="margin-left:10px"></span>
    </div>
  </div>
  <div class="card" style="margin-top:14px">
    <h2>Notes</h2>
    <ul>
      <li>Free tier follows same-host links up to a modest limit and depth.</li>
      <li>Flags: broken (HTTP ≥ 400), excessive redirects, mixed content, oversized pages.</li>
      <li>Best for quick checks; for large crawls, upgrade infra later.</li>
    </ul>
  </div>
</div>
<script>
const $ = (id) => document.getElementById(id);

async function startScan(){
  const u = $("url").value.trim();
  if(!u){ $("label").innerHTML = "<small>Enter a URL first.</small>"; return; }
  const form = new FormData(); form.set("url", u);
  const r = await fetch("/api/scan", {{ method:"POST", body:form }});
  if(!r.ok){{ $("label").innerHTML = "<small>Failed to start</small>"; return; }}
  const {{ task_id }} = await r.json();
  const es = new EventSource("/api/scan/stream/" + task_id);
  es.onmessage = (e) => {{
    const st = JSON.parse(e.data);
    $("bar").style.width = (st.progress||0) + "%";
    $("label").innerHTML = "<small>" + (st.message || "") + "</small>";
    if(st.status === "done"){{
      es.close();
      if(st.report_id){{
        $("dl-json").href = "/report/" + st.report_id + ".json";
        $("dl-csv").href  = "/report/" + st.report_id + ".csv";
        $("dl-json").removeAttribute("aria-disabled");
        $("dl-csv").removeAttribute("aria-disabled");
        $("open-report").innerHTML = '<a class="btn" style="margin-left:8px" href="/report/' + st.report_id + '">Open Report</a>';
      }}
    }}
    if(st.status === "error"){{
      es.close();
      $("label").innerHTML = "<small style='color:#ef6f6c'>Error: " + (st.message||"") + "</small>";
    }}
  }};
}

$("start").addEventListener("click", startScan);
</script>
</body></html>"""

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(HOME_HTML)

# ----- Start scan & progress -----
from fastapi import BackgroundTasks
import uuid

@app.post("/api/scan")
def api_scan(url: str = Form(...), background_tasks: BackgroundTasks = None, email: Optional[str] = Form(None)):
    u = (url or "").strip()
    if not u.startswith("http"):
        raise HTTPException(status_code=400, detail="Enter a full URL starting with http(s)://")
    task_id = uuid.uuid4().hex
    PROGRESS[task_id] = {"status": "queued", "progress": 0, "total": 100, "report_id": None, "message": "Queued"}
    background_tasks.add_task(run_crawl_job, task_id, u, email)
    return {"task_id": task_id}

@app.get("/api/scan/status/{task_id}")
def scan_status(task_id: str):
    st = PROGRESS.get(task_id)
    if not st:
        raise HTTPException(status_code=404, detail="Unknown task")
    return st

@app.get("/api/scan/stream/{task_id}")
async def scan_stream(task_id: str):
    async def gen():
        last = None
        while True:
            st = PROGRESS.get(task_id)
            if not st:
                yield "event: error\ndata: {\"message\":\"unknown task\"}\n\n"
                return
            payload = json.dumps(st)
            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload
            if st.get("status") in ("done", "error"):
                return
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream")

# ----- Report viewing -----
def _report_page(rid: int, data: Dict) -> str:
    s = data.get("summary", {})
    pages = data.get("pages", [])
    issues = data.get("issues", [])
    return f"""<!doctype html><html><head>{_head(f"LinkWatch — Report #{rid}")}</head>
<body><div class="wrap">
  <div class="card">
    <h1>Report #{rid}</h1>
    <p><strong>URL:</strong> {s.get("start_url","")}</p>
    <p><strong>Scanned:</strong> {s.get("scanned",0)} pages
       • <strong>Broken:</strong> {s.get("broken",0)}
       • <strong>Redirects:</strong> {s.get("redirects",0)}
       • <strong>Mixed:</strong> {s.get("mixed",0)}
       • <strong>Large:</strong> {s.get("large",0)}</p>
    <div>
      <a class="btn" href="/report/{rid}.json">Download JSON</a>
      <a class="btn" style="margin-left:8px" href="/report/{rid}.csv">Download CSV</a>
      <a class="btn" style="margin-left:8px" href="/">New Scan</a>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <h2>Issues</h2>
    {"<p>No issues.</p>" if not issues else ""}
    {"<table><thead><tr><th>Type</th><th>From</th><th>To</th><th>Status</th><th>Redirects</th><th>Mixed</th></tr></thead><tbody>" if issues else ""}
    { "".join(f"<tr><td>{i.get('type','')}</td><td>{i.get('from','')}</td><td>{i.get('to','')}</td><td>{i.get('status','')}</td><td>{i.get('redirects',0)}</td><td>{'yes' if i.get('mixed') else 'no'}</td></tr>" for i in issues) if issues else "" }
    {"</tbody></table>" if issues else ""}
  </div>

  <div class="card" style="margin-top:14px">
    <h2>Pages</h2>
    {"<p>No pages recorded.</p>" if not pages else ""}
    {"<table><thead><tr><th>Title</th><th>URL</th><th>Status</th><th>Bytes</th><th>Redirects</th><th>Mixed</th></tr></thead><tbody>" if pages else ""}
    { "".join(f"<tr><td>{(p.get('title') or '')}</td><td>{p.get('url','')}</td><td>{p.get('status','')}</td><td>{p.get('bytes',0)}</td><td>{p.get('redirects',0)}</td><td>{'yes' if p.get('mixed') else 'no'}</td></tr>" for p in pages) if pages else "" }
    {"</tbody></table>" if pages else ""}
  </div>
</div></body></html>"""

@app.get("/report/{report_id}", response_class=HTMLResponse)
def report_page(report_id: int):
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT report_data FROM reports WHERE id=%s" if DB_IS_PG else "SELECT report_data FROM reports WHERE id=?"
        cur.execute(q, (report_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        data = row[0]
        if isinstance(data, str):
            data = json.loads(data)
    return HTMLResponse(_report_page(report_id, data))

# ----- Downloads (JSON/CSV) -----
@app.get("/report/{report_id}.json")
def download_report_json(report_id: int):
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT report_data FROM reports WHERE id=%s" if DB_IS_PG else "SELECT report_data FROM reports WHERE id=?"
        cur.execute(q, (report_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        data = row[0]
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {"error": "Malformed report_data"}
        body = json.dumps(data, indent=2)
        return FastAPIResponse(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="linkwatch-report-{report_id}.json"'}
        )

@app.get("/report/{report_id}.csv")
def download_report_csv(report_id: int):
    with db_conn() as con:
        cur = con.cursor()
        q = "SELECT report_data FROM reports WHERE id=%s" if DB_IS_PG else "SELECT report_data FROM reports WHERE id=?"
        cur.execute(q, (report_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        data = row[0]
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                data = {"issues": []}
    issues = (data or {}).get("issues", [])
    if not isinstance(issues, list):
        issues = []

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "tag", "from", "to", "status", "redirects", "mixed"])
    for it in issues:
        w.writerow([
            it.get("type", ""),
            it.get("tag", ""),
            it.get("from", ""),
            it.get("to", ""),
            it.get("status", ""),
            it.get("redirects", 0),
            "yes" if it.get("mixed") else "no",
        ])
    csv_bytes = buf.getvalue().encode("utf-8")
    return FastAPIResponse(
        content=csv_bytes,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="linkwatch-report-{report_id}.csv"'}
    )

# ----- Favicon, robots, sitemap, health -----
FAVICON_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'>
  <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#7dd3fc'/><stop offset='100%' stop-color='#38bdf8'/></linearGradient></defs>
  <rect x='16' y='16' width='224' height='224' rx='48' fill='#0b1020'/>
  <g fill='none' stroke='url(#g)' stroke-width='20' stroke-linecap='round'>
    <circle cx='128' cy='128' r='72'/>
    <path d='M88 128h80M128 88v80'/>
  </g>
</svg>"""

@app.get("/favicon.svg")
def favicon():
    return FastAPIResponse(content=FAVICON_SVG, media_type="image/svg+xml")

@app.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request):
    base = str(request.base_url).rstrip("/")
    return PlainTextResponse(f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n")

@app.get("/sitemap.xml")
def sitemap(request: Request):
    base = str(request.base_url).rstrip("/")
    urls = ["/", "/healthz"]
    body = "<?xml version='1.0' encoding='UTF-8'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>" + \
           "".join(f"<url><loc>{base}{p}</loc></url>" for p in urls) + "</urlset>"
    return FastAPIResponse(content=body, media_type="application/xml")

@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "0.2.0"}

# ----- Startup -----
@app.on_event("startup")
def _startup():
    print("[startup] Using Postgres" if DB_IS_PG else "[startup] Using SQLite")
    db_init()

# ----- Dev server -----
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT","8000")))
