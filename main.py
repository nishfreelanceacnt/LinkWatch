import os, json, time, re, uuid, threading, datetime, csv, io
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from fastapi import FastAPI, Request, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

# ---------- DB ----------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
HAS_PG = False
try:
    if DATABASE_URL:
        import psycopg2
        import psycopg2.extras
        HAS_PG = True
except Exception:
    HAS_PG = False

import sqlite3

def db_conn():
    if HAS_PG:
        return psycopg2.connect(DATABASE_URL)
    else:
        # local sqlite fallback
        return sqlite3.connect("linkwatch.db")

def db_init():
    with db_conn() as con:
        cur = con.cursor()
        if HAS_PG:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id UUID PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    report_json JSONB NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """)
        else:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
        con.commit()

def db_insert_report(report_id: str, target_url: str, report: Dict):
    with db_conn() as con:
        cur = con.cursor()
        if HAS_PG:
            cur.execute(
                "INSERT INTO reports(id, target_url, report_json, created_at) VALUES (%s,%s,%s,NOW())",
                (report_id, target_url, psycopg2.extras.Json(report)),
            )
        else:
            cur.execute(
                "INSERT INTO reports(id, target_url, report_json, created_at) VALUES (?, ?, ?, ?)",
                (report_id, target_url, json.dumps(report), datetime.datetime.utcnow().isoformat() + "Z"),
            )
        con.commit()

def db_get_report(report_id: str) -> Optional[Dict]:
    with db_conn() as con:
        cur = con.cursor()
        if HAS_PG:
            cur.execute("SELECT report_json FROM reports WHERE id=%s", (report_id,))
            row = cur.fetchone()
            if not row:
                return None
            return row[0]
        else:
            cur.execute("SELECT report_json FROM reports WHERE id=?", (report_id,))
            row = cur.fetchone()
            if not row:
                return None
            return json.loads(row[0])

# ---------- App ----------
app = FastAPI(title="LinkWatch", version="0.3.0")
app.add_middleware(GZipMiddleware)

# CORS (open by default; tighten if needed)
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "*")
cors_origins = ["*"] if CORS_ALLOW_ORIGINS.strip() == "*" else [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Security headers ----------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return resp

# ---------- Branding assets ----------
LOGO_SVG = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'>
  <defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
    <stop offset='0%' stop-color='#7aa2ff'/><stop offset='100%' stop-color='#55e3c2'/></linearGradient></defs>
  <rect x='16' y='16' width='224' height='224' rx='48' fill='#0b1020'/>
  <rect x='24' y='24' width='208' height='208' rx='40' fill='url(#g)' opacity='0.10'/>
  <g fill='#eaf0ff'>
    <circle cx='110' cy='128' r='54' fill='none' stroke='#eaf0ff' stroke-width='10'/>
    <line x1='158' y1='176' x2='204' y2='222' stroke='#eaf0ff' stroke-width='12' stroke-linecap='round'/>
  </g>
</svg>"""

@app.get("/logo.svg")
def logo_svg():
    return Response(content=LOGO_SVG, media_type="image/svg+xml")

@app.get("/favicon.svg")
def favicon_svg():
    return Response(content=LOGO_SVG, media_type="image/svg+xml")

# ---------- HTML head & styles ----------
def _head(title: str) -> str:
    return f"""
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="icon" href="/favicon.svg">
<title>{title}</title>
<style>
  :root{{--bg:#0b1020;--card:#121933;--muted:#8da2d0;--text:#eef2ff;--accent:#7aa2ff;--ok:#55d38a;--warn:#e9c46a;--bad:#ef6f6c}}
  *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto}}
  .wrap{{max-width:960px;margin:40px auto;padding:0 16px}}
  .card{{background:var(--card);border-radius:16px;padding:22px;box-shadow:0 4px 24px rgba(0,0,0,.25)}}
  h1{{margin:0 0 6px}} p{{margin:0 0 16px;color:var(--muted)}}
  .row{{display:grid;grid-template-columns:1fr auto;gap:12px}}
  input,button{{padding:10px 12px;border-radius:10px;border:1px solid #2a3769;background:#0e1630;color:var(--text)}}
  button{{background:var(--accent);border:none;color:#04122d;font-weight:700;cursor:pointer}}
  .btn{{display:inline-block;padding:8px 12px;border-radius:8px;border:1px solid #233366;background:#0e1630;color:#eaf0ff;text-decoration:none}}
  table{{width:100%;border-collapse:collapse;margin-top:10px}}
  th,td{{padding:8px;border-bottom:1px solid #233366;text-align:left;vertical-align:top}}
  small{{color:var(--muted)}}
</style>
"""

def home_html() -> str:
    return """<!doctype html><html><head>__HEAD__</head>
<body><div class="wrap">
  <div class="card">
    <h1>LinkWatch</h1>
    <p>Scan a site for broken links, excessive redirects, mixed content, and large pages. (Free tier limits apply.)</p>
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
      <li>Same-origin crawl with limits to keep it snappy on free tiers.</li>
      <li>Flags: broken (HTTP ≥ 400), excessive redirects, mixed content over HTTPS, oversized pages.</li>
      <li>Use the JSON/CSV to fix in batches or archive results.</li>
    </ul>
  </div>
</div>
<script>
const $ = (id) => document.getElementById(id);

async function startScan(){
  const u = $("url").value.trim();
  if(!u){ $("label").innerHTML = "<small>Enter a URL first.</small>"; return; }
  $("bar").style.width = "0%";
  $("label").innerHTML = "<small>Starting…</small>";
  $("dl-json").setAttribute("aria-disabled","true");
  $("dl-csv").setAttribute("aria-disabled","true");
  $("open-report").innerHTML = "";

  const form = new FormData(); form.set("url", u);
  const r = await fetch("/api/scan", { method:"POST", body:form });
  if(!r.ok){ $("label").innerHTML = "<small>Failed to start</small>"; return; }
  const data = await r.json();
  const task_id = data.task_id;
  const es = new EventSource("/api/scan/stream/" + task_id);
  es.onmessage = (e) => {
    const st = JSON.parse(e.data);
    $("bar").style.width = (st.progress||0) + "%";
    $("label").innerHTML = "<small>" + (st.message || "") + "</small>";
    if(st.status === "done"){
      es.close();
      if(st.report_id){
        $("dl-json").href = "/report/" + st.report_id + ".json";
        $("dl-csv").href  = "/report/" + st.report_id + ".csv";
        $("dl-json").removeAttribute("aria-disabled");
        $("dl-csv").removeAttribute("aria-disabled");
        $("open-report").innerHTML = '<a class="btn" style="margin-left:8px" href="/report/' + st.report_id + '">Open Report</a>';
      }
    }
    if(st.status === "error"){
      es.close();
      $("label").innerHTML = "<small style='color:#ef6f6c'>Error: " + (st.message||"") + "</small>";
    }
  };
}

$("start").addEventListener("click", startScan);
</script>
</body></html>""".replace("__HEAD__", _head("LinkWatch — Broken Links & Issues Scanner"))

# ---------- Limits / Config ----------
MAX_PAGES = int(os.getenv("LW_MAX_PAGES", "80"))
MAX_DEPTH = int(os.getenv("LW_MAX_DEPTH", "2"))
TIMEOUT   = float(os.getenv("LW_TIMEOUT", "12.0"))
LARGE_BYTES = int(os.getenv("LW_LARGE_BYTES", str(1_500_000)))  # 1.5MB default

USER_AGENT = os.getenv("LW_UA", "LinkWatch/0.3 (+https://linkwatch)")
HEADERS = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

# ---------- Tasks (progress for SSE) ----------
# tasks[task_id] = {"status": "running|done|error", "progress": int, "message": str, "report_id": str|None}
tasks: Dict[str, Dict] = {}
tasks_lock = threading.Lock()

def set_task(task_id: str, **kwargs):
    with tasks_lock:
        st = tasks.get(task_id, {})
        st.update(kwargs)
        tasks[task_id] = st

def get_task(task_id: str) -> Optional[Dict]:
    with tasks_lock:
        return dict(tasks.get(task_id) or {})  # copy

# ---------- Crawler helpers ----------
_href_like = re.compile(r"^(?:https?:)?//|/|#|\.{1,2}/", re.I)

def normalize_url(base: str, link: str) -> Optional[str]:
    if not link:
        return None
    link = link.strip()
    if link.startswith("#") or link.lower().startswith("mailto:") or link.lower().startswith("javascript:"):
        return None
    # join relative links
    try:
        return urljoin(base, link)
    except Exception:
        return None

def same_origin(a: str, b: str) -> bool:
    try:
        ua, ub = urlparse(a), urlparse(b)
        return (ua.scheme, ua.hostname) == (ub.scheme, ub.hostname)
    except Exception:
        return False

def fetch_page(url: str) -> Tuple[int, bytes, requests.Response]:
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        status = r.status_code
        content = r.content or b""
        return status, content, r
    except Exception:
        return 0, b"", requests.Response()

def detect_mixed(page_url: str, html: str) -> bool:
    try:
        u = urlparse(page_url)
        if u.scheme != "https":
            return False
        soup = BeautifulSoup(html, "html.parser")
        tags = []
        tags += [t.get("src", "") for t in soup.find_all(["img","script","iframe","audio","video"]) if t.get("src")]
        tags += [t.get("href","") for t in soup.find_all(["link","a"]) if t.get("href")]
        for t in tags:
            if isinstance(t, str) and t.strip().lower().startswith("http:"):
                return True
        return False
    except Exception:
        return False

def crawl_site(task_id: str, start_url: str):
    set_task(task_id, status="running", progress=0, message="Fetching…")
    origin = urlparse(start_url)
    if origin.scheme not in ("http", "https") or not origin.netloc:
        set_task(task_id, status="error", message="Invalid URL")
        return

    visited: Set[str] = set()
    queue: List[Tuple[str,int]] = [(start_url, 0)]

    pages: List[Dict] = []
    issues: List[Dict] = []

    total_target = MAX_PAGES
    seen = 0

    while queue and seen < MAX_PAGES:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        seen += 1

        set_task(task_id, progress=int((seen/total_target)*100), message=f"Crawling ({seen}/{total_target})… {url}")

        status, content, resp = fetch_page(url)
        size = len(content)
        redirects = len(getattr(resp, "history", []) or [])
        mixed = False
        title = ""
        final_url = getattr(resp, "url", url) or url

        if content and b"text/html" in (resp.headers.get("Content-Type","").encode("utf-8")):
            try:
                soup = BeautifulSoup(content, "html.parser")
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()
                mixed = detect_mixed(final_url, content.decode("utf-8", errors="ignore"))
                # discover links
                if depth < MAX_DEPTH:
                    for a in soup.find_all("a"):
                        href = a.get("href")
                        nu = normalize_url(final_url, href)
                        if nu and same_origin(start_url, nu) and nu not in visited:
                            queue.append((nu, depth+1))
            except Exception:
                pass

        pages.append({
            "title": title or "(no title)",
            "url": final_url,
            "status": status,
            "bytes": size,
            "redirects": redirects,
            "mixed": bool(mixed),
        })

        # flag issues
        if status >= 400 or status == 0:
            issues.append({"type":"broken","from":url,"to":final_url,"status":status,"redirects":redirects,"mixed": mixed})
        elif redirects >= 3:
            issues.append({"type":"redirect","from":url,"to":final_url,"status":status,"redirects":redirects,"mixed": mixed})
        elif mixed:
            issues.append({"type":"mixed","from":url,"to":final_url,"status":status,"redirects":redirects,"mixed": mixed})
        elif size >= LARGE_BYTES:
            issues.append({"type":"large","from":url,"to":final_url,"status":status,"redirects":redirects,"mixed": mixed})

    # summary
    report = {
        "target": start_url,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "limits": {"max_pages": MAX_PAGES, "max_depth": MAX_DEPTH, "timeout_sec": TIMEOUT, "large_bytes": LARGE_BYTES},
        "totals": {
            "pages": len(pages),
            "broken": len([i for i in issues if i["type"]=="broken"]),
            "redirects": len([i for i in issues if i["type"]=="redirect"]),
            "mixed": len([i for i in issues if i["type"]=="mixed"]),
            "large": len([i for i in issues if i["type"]=="large"]),
        },
        "issues": issues,
        "pages": pages,
    }

    report_id = uuid.uuid4().hex
    try:
        db_insert_report(report_id, start_url, report)
    except Exception as e:
        set_task(task_id, status="error", message=f"Failed to save report: {e}")
        return

    set_task(task_id, status="done", progress=100, message=f"Done. {report['totals']['pages']} pages.", report_id=report_id)

# ---------- Pages ----------
@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(home_html())

# ---------- API: start scan ----------
@app.post("/api/scan")
def api_scan(url: str = Form(...)):
    task_id = uuid.uuid4().hex
    set_task(task_id, status="running", progress=0, message="Starting…", report_id=None)
    th = threading.Thread(target=crawl_site, args=(task_id, url), daemon=True)
    th.start()
    return {"task_id": task_id}

# ---------- API: stream progress (SSE) ----------
@app.get("/api/scan/stream/{task_id}")
def api_stream(task_id: str):
    def gen():
        # stream current snapshot until done/error
        last = None
        while True:
            st = get_task(task_id)
            if not st:
                # unknown task id: end with error snapshot
                yield f"data: {json.dumps({'status':'error','message':'Unknown task'})}\n\n"
                return
            if st != last:
                yield f"data: {json.dumps(st)}\n\n"
                last = st
            if st.get("status") in ("done", "error"):
                return
            time.sleep(0.5)
    return StreamingResponse(gen(), media_type="text/event-stream")

# ---------- Reports ----------
@app.get("/report/{report_id}", response_class=HTMLResponse)
def report_page(report_id: str):
    rep = db_get_report(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")
    t = rep["totals"]
    # simple summary page
    body = f"""<!doctype html><html><head>{_head("LinkWatch — Report")}</head>
<body><div class="wrap">
  <div class="card">
    <h1>Report</h1>
    <p><small>Target:</small> <a href="{rep['target']}" target="_blank" rel="noopener">{rep['target']}</a></p>
    <p><small>Generated:</small> {rep['generated_at']}</p>
    <h3>Totals</h3>
    <table>
      <tr><th>Total pages</th><td>{t['pages']}</td></tr>
      <tr><th>Broken links</th><td>{t['broken']}</td></tr>
      <tr><th>Redirect issues</th><td>{t['redirects']}</td></tr>
      <tr><th>Mixed content</th><td>{t['mixed']}</td></tr>
      <tr><th>Large pages</th><td>{t['large']}</td></tr>
    </table>
    <p style="margin-top:10px">
      <a class="btn" href="/report/{report_id}.json">Download JSON</a>
      <a class="btn" href="/report/{report_id}.csv" style="margin-left:8px">Download CSV</a>
    </p>
  </div>
  <div class="card" style="margin-top:14px">
    <h2>Pages</h2>
    <table>
      <thead><tr><th>Title</th><th>URL</th><th>Status</th><th>Bytes</th><th>Redirects</th><th>Mixed?</th></tr></thead>
      <tbody>
      {''.join(f"<tr><td>{(p['title'] or '').replace('<','&lt;')}</td><td><a href='{p['url']}' target='_blank' rel='noopener'>{p['url']}</a></td><td>{p['status']}</td><td>{p['bytes']}</td><td>{p['redirects']}</td><td>{'yes' if p['mixed'] else 'no'}</td></tr>" for p in rep['pages'])}
      </tbody>
    </table>
  </div>
</div></body></html>"""
    return HTMLResponse(body)

@app.get("/report/{report_id}.json")
def report_json(report_id: str):
    rep = db_get_report(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse(rep)

@app.get("/report/{report_id}.csv")
def report_csv(report_id: str):
    rep = db_get_report(report_id)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")
    # Flatten issues into CSV rows (Type, From, To, Status, Redirects, Mixed?)
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["Type","From","To","Status","Redirects","Mixed?"])
    for i in rep.get("issues", []):
        w.writerow([i.get("type",""), i.get("from",""), i.get("to",""), i.get("status",""), i.get("redirects",""), "yes" if i.get("mixed") else "no"])
    return Response(content=output.getvalue(), media_type="text/csv")

# ---------- SEO ----------
@app.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request):
    base = str(request.base_url).rstrip("/")
    return PlainTextResponse(f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n")

@app.get("/sitemap.xml")
def sitemap(request: Request):
    base = str(request.base_url).rstrip("/")
    urls = ["/", "/healthz"]
    items = "".join(f"<url><loc>{base}{p}</loc></url>" for p in urls)
    xml = f"<?xml version='1.0' encoding='UTF-8'?><urlset xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>{items}</urlset>"
    return Response(content=xml, media_type="application/xml")

# ---------- Health ----------
@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "0.3.0"}

# ---------- Startup ----------
@app.on_event("startup")
def _startup():
    db_init()
    if HAS_PG:
        print("[startup] Using Postgres")
    else:
        print("[startup] Using SQLite fallback")

# ---------- Uvicorn (local) ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT","8000")))
