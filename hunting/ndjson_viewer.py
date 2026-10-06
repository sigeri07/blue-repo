#!/usr/bin/env python3
"""
ndjson_viewer.py - Viewer log Elasticsearch NDJSON ala Kibana Discover, tanpa Elastic.

Server lokal (hanya 127.0.0.1) + halaman HTML dengan filter via AJAX.
Hanya library standar Python 3.8+ (sqlite3, http.server). Tanpa pip install.

    python3 ndjson_viewer.py HuntForExecution.ndjson            # buka http://127.0.0.1:8000
    python3 ndjson_viewer.py HuntForExecution.ndjson --port 9000
    python3 ndjson_viewer.py HuntForExecution.ndjson --rebuild   # bangun ulang indeks

Pertama kali jalan, dibuat indeks SQLite (<nama>.ndjson.sqlite, beberapa detik).
Data asli tidak diubah; detail event dibaca langsung dari file NDJSON.

Fitur: pencarian teks (AND, -kata untuk exclude, mode regex), facet dataset/EID/proses/user/host
dengan hitungan, filter waktu (drag pada histogram), preset hunting, panel detail JSON,
sorting, paginasi, ekspor CSV hasil filter.
"""
import argparse
import csv
import io
import json
import os
import re
import sqlite3
import sys
import threading
import webbrowser
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

FACETS = ["dataset", "eid", "proc", "user", "host"]


# ----------------------------------------------------------------- indexing
def g(d, path, default=""):
    cur = d
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    if isinstance(cur, list):
        return " ".join(map(str, cur))
    return cur if cur is not None else default


def first(d, *paths):
    for p in paths:
        v = g(d, p)
        if v not in ("", None):
            return str(v)
    return ""


def base(p):
    return re.split(r"[\\/]", str(p))[-1] if p else ""


def to_epoch(ts):
    try:
        return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
    except Exception:
        return 0


def derive(s):
    ed = g(s, "winlog.event_data", {}) or {}
    msg = s.get("message", "") or ""
    eid = str(first(s, "winlog.event_id", "event.code") or g(s, "event.action"))
    proc = first(s, "process.name") or base(ed.get("Application", ""))
    parent = first(s, "process.parent.name")
    cmd = first(s, "process.command_line", "winlog.event_data.CommandLine")
    user = first(s, "winlog.event_data.User", "user.name", "winlog.user.name",
                 "winlog.event_data.SubjectUserName")
    dst_ip = first(s, "destination.ip") or ed.get("DestAddress", "")
    dst_port = first(s, "destination.port") or ed.get("DestPort", "")
    dst = f"{dst_ip}:{dst_port}" if dst_ip else ""
    target = first(s, "file.path", "registry.path", "winlog.event_data.TargetFilename",
                   "winlog.event_data.TargetObject")
    head = " ".join(msg.split())[:300]
    if cmd:
        summary = (f"{parent} → " if parent else "") + f"{proc}: {cmd}"
    elif dst:
        summary = f"{proc} → {dst}"
    elif target:
        summary = f"{proc} · {target}"
    else:
        summary = head
    text = " ".join([summary, cmd, target, dst, user, first(s, "process.executable"),
                     " ".join(msg.split())[:4000]]).lower()
    return dict(dataset=g(s, "data_stream.dataset"), eid=eid, host=g(s, "host.name"),
                user=user, proc=proc, parent=parent, cmd=cmd, dst=dst, target=target,
                summary=summary[:1000], text=text)


def build_index(nd, db):
    if os.path.exists(db):
        os.remove(db)
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE events(id INTEGER PRIMARY KEY, off INTEGER, len INTEGER,
        ts TEXT, epoch INTEGER, dataset TEXT, eid TEXT, host TEXT, user TEXT, proc TEXT,
        parent TEXT, cmd TEXT, dst TEXT, target TEXT, summary TEXT, text TEXT)""")
    n = bad = 0
    batch = []
    with open(nd, "rb") as f:
        off = 0
        for raw in f:
            ln = len(raw)
            try:
                s = json.loads(raw)["_source"]
                d = derive(s)
                ts = s.get("@timestamp", "")
                batch.append((off, ln, ts, to_epoch(ts), d["dataset"], d["eid"], d["host"],
                              d["user"], d["proc"], d["parent"], d["cmd"], d["dst"],
                              d["target"], d["summary"], d["text"]))
                n += 1
            except Exception:
                bad += 1
            off += ln
            if len(batch) >= 2000:
                con.executemany("INSERT INTO events(off,len,ts,epoch,dataset,eid,host,user,proc,parent,cmd,dst,target,summary,text) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                batch = []
    if batch:
        con.executemany("INSERT INTO events(off,len,ts,epoch,dataset,eid,host,user,proc,parent,cmd,dst,target,summary,text) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
    for c in ("epoch", "dataset", "eid", "proc", "user", "host"):
        con.execute(f"CREATE INDEX i_{c} ON events({c})")
    con.commit()
    con.close()
    print(f"[+] indeks selesai: {n} event, {bad} baris rusak", file=sys.stderr)


# ----------------------------------------------------------------- query
@lru_cache(maxsize=64)
def _rx(p):
    return re.compile(p, re.I)


def _regexp(pat, val):
    try:
        return 1 if val and _rx(pat).search(val) else 0
    except re.error:
        return 0


_RX_CACHE = {}
_RX_LOCK = threading.Lock()


def regex_ids(con, pat):
    """Satu kali scan regex per pola, hasilnya (daftar id) di-cache -> facet/histogram/halaman cepat."""
    with _RX_LOCK:
        if pat not in _RX_CACHE:
            rx = _rx(pat)
            ids = [r[0] for r in con.execute("SELECT id, text FROM events") if rx.search(r[1] or "")]
            if len(_RX_CACHE) > 20:
                _RX_CACHE.pop(next(iter(_RX_CACHE)))
            _RX_CACHE[pat] = json.dumps(ids)
        return _RX_CACHE[pat]


def connect(db):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, check_same_thread=False)
    con.create_function("REGEXP", 2, _regexp)
    con.row_factory = sqlite3.Row
    return con


def where(p, con, skip=None):
    """p: dict hasil parse_qs. skip: nama facet yang diabaikan (untuk hitungan facet)."""
    w, a = [], []
    q = (p.get("q", [""])[0]).strip()
    if q:
        if p.get("regex", ["0"])[0] == "1":
            re.compile(q)  # validasi -> re.error ditangkap handler
            w.append("id IN (SELECT value FROM json_each(?))")
            a.append(regex_ids(con, q))
        else:
            for t in q.lower().split():
                if t.startswith("-") and len(t) > 1:
                    w.append("text NOT LIKE ?")
                    a.append(f"%{t[1:]}%")
                else:
                    w.append("text LIKE ?")
                    a.append(f"%{t}%")
    for f in FACETS:
        if f == skip:
            continue
        vals = p.get(f)
        if vals:
            w.append(f"{f} IN ({','.join('?' * len(vals))})")
            a.extend(vals)
    if p.get("from", [""])[0]:
        w.append("epoch >= ?")
        a.append(int(p["from"][0]))
    if p.get("to", [""])[0]:
        w.append("epoch <= ?")
        a.append(int(p["to"][0]))
    return (" WHERE " + " AND ".join(w)) if w else "", a


COLS = "id,ts,dataset,eid,host,user,proc,parent,dst,target,summary"


class H(BaseHTTPRequestHandler):
    server_version = "ndjson-viewer"
    db = ""
    nd = ""

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        p = parse_qs(u.query)
        try:
            if u.path == "/":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            con = connect(self.db)
            try:
                if u.path == "/api/events":
                    return self._events(con, p)
                if u.path == "/api/facets":
                    return self._facets(con, p)
                if u.path == "/api/histogram":
                    return self._hist(con, p)
                if u.path == "/api/event":
                    return self._event(con, p)
                if u.path == "/api/export":
                    return self._export(con, p)
            finally:
                con.close()
            self._send(404, json.dumps({"error": "not found"}))
        except re.error as e:
            self._send(400, json.dumps({"error": f"regex tidak valid: {e}"}))
        except (ValueError, KeyError) as e:
            self._send(400, json.dumps({"error": str(e)}))
        except BrokenPipeError:
            pass
        except Exception as e:  # noqa
            self._send(500, json.dumps({"error": str(e)}))

    def _events(self, con, p):
        wh, a = where(p, con)
        size = min(max(int(p.get("size", ["100"])[0]), 1), 500)
        page = max(int(p.get("page", ["0"])[0]), 0)
        order = "DESC" if p.get("order", ["asc"])[0] == "desc" else "ASC"
        total = con.execute(f"SELECT COUNT(*) FROM events{wh}", a).fetchone()[0]
        rows = con.execute(
            f"SELECT {COLS} FROM events{wh} ORDER BY epoch {order}, id {order} LIMIT ? OFFSET ?",
            a + [size, page * size]).fetchall()
        self._send(200, json.dumps({"total": total, "rows": [dict(r) for r in rows]}))

    def _facets(self, con, p):
        out = {}
        for f in FACETS:
            wh, a = where(p, con, skip=f)
            rows = con.execute(
                f"SELECT {f} v, COUNT(*) c FROM events{wh} GROUP BY {f} ORDER BY c DESC LIMIT 30", a).fetchall()
            out[f] = [{"v": r["v"], "c": r["c"]} for r in rows]
        self._send(200, json.dumps(out))

    def _hist(self, con, p):
        wh, a = where(p, con)
        bucket = max(int(p.get("bucket", ["3600"])[0]), 1)
        rows = con.execute(
            f"SELECT (epoch/{bucket})*{bucket} t, COUNT(*) c FROM events{wh} GROUP BY t ORDER BY t", a).fetchall()
        rng = con.execute("SELECT MIN(epoch), MAX(epoch) FROM events WHERE epoch>0").fetchone()
        self._send(200, json.dumps({"bucket": bucket, "min": rng[0], "max": rng[1],
                                    "data": [[r["t"], r["c"]] for r in rows]}))

    def _event(self, con, p):
        r = con.execute("SELECT off,len FROM events WHERE id=?", (int(p["id"][0]),)).fetchone()
        if not r:
            raise KeyError("event tidak ditemukan")
        with open(self.nd, "rb") as f:
            f.seek(r["off"])
            raw = f.read(r["len"])
        self._send(200, json.dumps(json.loads(raw), indent=2, ensure_ascii=False))

    def _export(self, con, p):
        wh, a = where(p, con)
        order = "DESC" if p.get("order", ["asc"])[0] == "desc" else "ASC"
        rows = con.execute(
            f"SELECT ts,dataset,eid,host,user,proc,parent,dst,target,summary FROM events{wh} "
            f"ORDER BY epoch {order}, id {order} LIMIT 100000", a).fetchall()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["timestamp", "dataset", "event_id", "host", "user", "process", "parent",
                    "destination", "target", "summary"])
        for r in rows:
            # cegah CSV/formula injection saat dibuka di Excel
            w.writerow([("'" + str(x)) if str(x) and str(x)[0] in "=+-@" else x for x in tuple(r)])
        self._send(200, buf.getvalue(), "text/csv; charset=utf-8",
                   {"Content-Disposition": 'attachment; filename="events_filtered.csv"'})


# ----------------------------------------------------------------- frontend
PAGE = r"""<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NDJSON Viewer</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--text:#1d2330;--muted:#6b7385;--line:#e2e5ec;--acc:#2f6feb;--accbg:#e8f0ff;--hi:#fff4cc;--bar:#7aa2f7}
@media (prefers-color-scheme:dark){:root{--bg:#12151c;--panel:#1a1e28;--text:#e6e9f0;--muted:#8d95a8;--line:#2a2f3d;--acc:#6e9bff;--accbg:#22304f;--hi:#4a3f12;--bar:#4a6fc4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line);padding:10px 14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
header h1{font-size:15px;margin:0 8px 0 0}
input[type=text],input[type=datetime-local],select{background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font:inherit}
#q{flex:1;min-width:240px}
button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px 10px;font:inherit;cursor:pointer}
button:hover{border-color:var(--acc)}button.on{background:var(--accbg);border-color:var(--acc)}
.layout{display:grid;grid-template-columns:260px 1fr;gap:12px;padding:12px 14px}
@media (max-width:860px){.layout{grid-template-columns:1fr}}
aside .grp{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-bottom:10px;padding:8px}
aside h3{margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.fv{display:flex;justify-content:space-between;gap:6px;padding:2px 4px;border-radius:4px;cursor:pointer;word-break:break-all}
.fv:hover{background:var(--accbg)}.fv.sel{background:var(--accbg);font-weight:600;outline:1px solid var(--acc)}
.fv .c{color:var(--muted);flex:none}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin-bottom:10px}
#hist{display:block;width:100%;height:80px;cursor:crosshair}
.bar{padding:6px 10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;color:var(--muted)}
.chips{display:flex;gap:6px;flex-wrap:wrap;padding:6px 10px}
.chip{background:var(--accbg);border:1px solid var(--acc);border-radius:99px;padding:1px 8px;cursor:pointer}
.presets{display:flex;gap:6px;flex-wrap:wrap;padding:8px 10px;border-top:1px solid var(--line)}
table{border-collapse:collapse;width:100%;table-layout:fixed}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
th{position:sticky;top:0;background:var(--panel);color:var(--muted);font-weight:600;cursor:pointer}
tbody tr{cursor:pointer}tbody tr:hover{background:var(--accbg)}
td.link:hover{color:var(--acc);text-decoration:underline}
td.sum{white-space:normal;word-break:break-all;max-height:3.9em}
mark{background:var(--hi);color:inherit;padding:0 1px}
#detail{position:fixed;top:0;right:0;bottom:0;width:min(640px,100vw);background:var(--panel);border-left:1px solid var(--line);box-shadow:-8px 0 24px #0003;transform:translateX(105%);transition:transform .15s;z-index:10;display:flex;flex-direction:column}
#detail.open{transform:none}
#detail .hd{display:flex;gap:8px;padding:10px;border-bottom:1px solid var(--line);align-items:center}
#detail pre{margin:0;padding:12px;overflow:auto;flex:1;font:12px/1.4 ui-monospace,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
.err{color:#d33;padding:8px 10px}
.mut{color:var(--muted)}
</style></head><body>
<header>
  <h1>NDJSON Viewer</h1>
  <input type="text" id="q" placeholder='Cari: powershell -windowsupdate  (spasi = AND, -kata = exclude)'>
  <button id="rx" title="Cari sebagai regular expression">.* regex</button>
  <input type="datetime-local" id="from" title="Dari (UTC)"><input type="datetime-local" id="to" title="Sampai (UTC)">
  <button id="reset">Reset</button>
  <button id="csv">⬇ CSV</button>
</header>
<div class="layout">
<aside id="facets"></aside>
<main>
  <div class="card"><svg id="hist"></svg><div class="bar"><span id="range"></span><span>· seret pada grafik untuk memilih rentang waktu (UTC)</span></div></div>
  <div class="card">
    <div class="chips" id="chips"></div>
    <div class="presets" id="presets"></div>
    <div class="bar"><b id="total" style="color:var(--text)"></b>
      <span style="flex:1"></span>
      <button id="prev">‹</button><span id="pg"></span><button id="next">›</button>
      <select id="size"><option>50</option><option selected>100</option><option>250</option><option>500</option></select>
    </div>
    <div class="err" id="err" hidden></div>
    <table><colgroup><col style="width:150px"><col style="width:120px"><col style="width:150px"><col style="width:130px"><col></colgroup>
      <thead><tr><th id="th-ts">Waktu (UTC) ↑</th><th>Dataset / EID</th><th>Proses</th><th>User</th><th>Ringkasan</th></tr></thead>
      <tbody id="rows"></tbody></table>
  </div>
</main></div>
<div id="detail"><div class="hd"><b id="dtitle">Detail</b><span style="flex:1"></span><button id="dcopy">Salin</button><button id="dclose">✕</button></div><pre id="djson"></pre></div>
<script>
const $=s=>document.querySelector(s);
const FAC=[['dataset','Dataset'],['eid','Event ID'],['proc','Proses'],['user','User'],['host','Host']];
const PRESETS=[
 ['PowerShell encoded','-e(nc\\w*)?\\s+[a-z0-9+/=]{20,}'],
 ['Download cradle','downloadstring|downloadfile|net\\.webclient|invoke-webrequest|\\biwr\\b|bitstransfer'],
 ['IEX','\\biex\\b|invoke-expression'],
 ['Obfuscation','frombase64string|deflatestream|gzipstream|-join\\s*\\[char\\]'],
 ['AMSI / Reflection','amsiutils|amsiinitfailed|reflection\\.assembly|virtualalloc|add-type\\s+-memberdefinition'],
 ['Offensive tools','mimikatz|powersploit|powerview|sharphound|bloodhound|rubeus|meterpreter|invoke-shellcode|cobalt'],
 ['Defender tamper','msmpeng|set-mppreference|windefend|disablerealtimemonitoring|exclusionpath'],
 ['LOLBins','\\b(certutil|regsvr32|rundll32|mshta|bitsadmin|msbuild|installutil|wmic|cscript|wscript|forfiles)\\.exe'],
 ['Eksekusi dari Temp/AppData','\\\\(temp|appdata|downloads|programdata|users\\\\public)\\\\[^ ]*\\.(exe|dll|ps1|bat|vbs|js)'],
 ['Discovery','whoami|net\\s+(user|group|localgroup)|nltest|systeminfo|ipconfig\\s*/all|tasklist']
];
const S={q:'',rx:false,sel:{dataset:[],eid:[],proc:[],user:[],host:[]},from:'',to:'',page:0,size:100,order:'asc',total:0,min:0,max:0};
let hist=null,ctl=null,timer=null;
function qs(extra){const p=new URLSearchParams();if(S.q)p.set('q',S.q);if(S.rx)p.set('regex','1');
 for(const k in S.sel)S.sel[k].forEach(v=>p.append(k,v));if(S.from)p.set('from',S.from);if(S.to)p.set('to',S.to);
 for(const k in extra)p.set(k,extra[k]);return p.toString()}
const fmt=e=>new Date(e*1000).toISOString().slice(0,19).replace('T',' ');
async function api(path,extra){if(ctl)ctl.abort();ctl=new AbortController();
 const r=await fetch(path+'?'+qs(extra),{signal:ctl.signal});const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
async function apiNoAbort(path,extra){const r=await fetch(path+'?'+qs(extra));const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function esc(s){return String(s??'')}
function hl(el,text){ // sorot kata (non-regex), aman: tanpa innerHTML
 el.textContent='';const terms=(!S.rx&&S.q)?S.q.split(/\s+/).filter(t=>t&&t[0]!=='-'):[];
 if(!terms.length){el.textContent=text;return}
 const re=new RegExp('('+terms.map(t=>t.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('|')+')','ig');
 text.split(re).forEach((part,i)=>{if(i%2){const m=document.createElement('mark');m.textContent=part;el.append(m)}else el.append(part)})}
async function load(resetPage){
 if(resetPage)S.page=0;$('#err').hidden=true;$('#rows').style.opacity=.4;$('#total').textContent='memuat…';
 try{
  const [ev,fc]=await Promise.all([api('/api/events',{page:S.page,size:S.size,order:S.order}),apiNoAbort('/api/facets')]);
  S.total=ev.total;$('#rows').style.opacity=1;renderRows(ev.rows);renderFacets(fc);renderChips();loadHist();
 }catch(e){if(e.name==='AbortError')return;$('#err').textContent='⚠ '+e.message;$('#err').hidden=false}}
function renderRows(rows){
 const tb=$('#rows');tb.textContent='';
 rows.forEach(r=>{const tr=document.createElement('tr');
  const c=(t,cls,onclick)=>{const td=document.createElement('td');if(cls)td.className=cls;td.textContent=t;td.title=t;if(onclick)td.onclick=e=>{e.stopPropagation();onclick()};tr.append(td);return td};
  c(r.ts.slice(0,19).replace('T',' '));c(r.dataset.replace(/^windows\.|^system\./,'')+' / '+r.eid);
  c(r.proc,'link',()=>addSel('proc',r.proc));c(r.user,'link',()=>addSel('user',r.user));
  const s=c('', 'sum');s.title=r.summary;hl(s,r.summary.slice(0,400));
  tr.onclick=()=>openDetail(r);tb.append(tr)});
 const pages=Math.max(1,Math.ceil(S.total/S.size));
 $('#total').textContent=S.total.toLocaleString()+' event';$('#pg').textContent=(S.page+1)+' / '+pages;
 $('#prev').disabled=S.page<=0;$('#next').disabled=S.page+1>=pages}
function renderFacets(fc){
 const root=$('#facets');root.textContent='';
 FAC.forEach(([k,label])=>{const g=document.createElement('div');g.className='grp';
  const h=document.createElement('h3');h.textContent=label;g.append(h);
  const shown=new Set(fc[k].map(x=>x.v));
  S.sel[k].filter(v=>!shown.has(v)).forEach(v=>fc[k].unshift({v,c:0}));
  fc[k].forEach(x=>{const d=document.createElement('div');d.className='fv'+(S.sel[k].includes(x.v)?' sel':'');
   const a=document.createElement('span');a.textContent=x.v||'(kosong)';const c=document.createElement('span');c.className='c';c.textContent=x.c.toLocaleString();
   d.append(a,c);d.onclick=()=>toggle(k,x.v);g.append(d)});root.append(g)})}
function toggle(k,v){const a=S.sel[k],i=a.indexOf(v);i<0?a.push(v):a.splice(i,1);load(true)}
function addSel(k,v){if(!S.sel[k].includes(v)){S.sel[k].push(v);load(true)}}
function renderChips(){const c=$('#chips');c.textContent='';
 const add=(t,f)=>{const s=document.createElement('span');s.className='chip';s.textContent=t+' ✕';s.onclick=f;c.append(s)};
 for(const k in S.sel)S.sel[k].forEach(v=>add(k+': '+(v||'(kosong)'),()=>toggle(k,v)));
 if(S.from||S.to)add('waktu: '+(S.from?fmt(S.from):'…')+' → '+(S.to?fmt(S.to):'…'),()=>{S.from=S.to='';$('#from').value=$('#to').value='';load(true)});
 if(!c.children.length)c.innerHTML='<span class="mut">Belum ada filter. Klik nilai di panel kiri, atau pilih preset di bawah.</span>'}
function renderPresets(){const p=$('#presets');const l=document.createElement('span');l.className='mut';l.textContent='Preset hunting:';p.append(l);
 PRESETS.forEach(([n,rx])=>{const b=document.createElement('button');b.textContent=n;b.onclick=()=>{S.q=rx;S.rx=true;$('#q').value=rx;$('#rx').classList.add('on');load(true)};p.append(b)})}
async function loadHist(){
 let min=S.min,max=S.max;
 if(!min){const j=await apiNoAbort('/api/histogram',{bucket:3600});S.min=j.min;S.max=j.max;min=j.min;max=j.max}
 const lo=S.from?+S.from:min,hi=S.to?+S.to:max;const span=Math.max(hi-lo,60);
 const bucket=Math.max(60,Math.ceil(span/90/60)*60);
 const j=await apiNoAbort('/api/histogram',{bucket});hist={lo,hi,bucket,data:j.data};drawHist()}
function drawHist(){
 const svg=$('#hist');const W=svg.clientWidth||800,Hh=80;svg.setAttribute('viewBox','0 0 '+W+' '+Hh);svg.textContent='';
 if(!hist)return;const {lo,hi,bucket,data}=hist;const mx=Math.max(1,...data.map(d=>d[1]));
 const x=t=>(t-lo)/(hi-lo+bucket)*W;const bw=Math.max(1,bucket/(hi-lo+bucket)*W-1);
 data.forEach(([t,c])=>{if(t<lo-bucket||t>hi)return;const r=document.createElementNS('http://www.w3.org/2000/svg','rect');
  const h=Math.max(1,c/mx*(Hh-6));r.setAttribute('x',x(t));r.setAttribute('y',Hh-h);r.setAttribute('width',bw);r.setAttribute('height',h);r.setAttribute('fill','var(--bar)');
  const ti=document.createElementNS('http://www.w3.org/2000/svg','title');ti.textContent=fmt(t)+' UTC — '+c+' event';r.append(ti);svg.append(r)});
 $('#range').textContent=fmt(lo)+' → '+fmt(hi)+' (bucket '+Math.round(bucket/60)+' mnt)'}
(function brush(){const svg=$('#hist');let x0=null,box=null;
 const px=e=>{const r=svg.getBoundingClientRect();return Math.min(Math.max(e.clientX-r.left,0),r.width)};
 svg.onmousedown=e=>{x0=px(e);box=document.createElementNS('http://www.w3.org/2000/svg','rect');box.setAttribute('fill','var(--acc)');box.setAttribute('opacity','.25');box.setAttribute('y',0);box.setAttribute('height',80);svg.append(box);e.preventDefault()};
 window.addEventListener('mousemove',e=>{if(x0===null)return;const x1=px(e),a=Math.min(x0,x1),b=Math.max(x0,x1);const sc=svg.clientWidth/(svg.viewBox.baseVal.width||1);box.setAttribute('x',a/sc);box.setAttribute('width',(b-a)/sc)});
 window.addEventListener('mouseup',e=>{if(x0===null)return;const x1=px(e),w=svg.clientWidth;const a=Math.min(x0,x1),b=Math.max(x0,x1);x0=null;
  if(!hist||b-a<4){drawHist();return}
  const span=hist.hi-hist.lo+hist.bucket;S.from=String(Math.floor(hist.lo+a/w*span));S.to=String(Math.ceil(hist.lo+b/w*span));
  $('#from').value=new Date(S.from*1000).toISOString().slice(0,16);$('#to').value=new Date(S.to*1000).toISOString().slice(0,16);load(true)})})();
async function openDetail(r){$('#dtitle').textContent=r.ts.slice(0,19).replace('T',' ')+' · '+r.dataset+' / '+r.eid;
 $('#djson').textContent='memuat…';$('#detail').classList.add('open');
 try{const x=await fetch('/api/event?id='+r.id);$('#djson').textContent=await x.text()}catch(e){$('#djson').textContent=e.message}}
$('#dclose').onclick=()=>$('#detail').classList.remove('open');
document.addEventListener('keydown',e=>{if(e.key==='Escape')$('#detail').classList.remove('open')});
$('#dcopy').onclick=()=>navigator.clipboard&&navigator.clipboard.writeText($('#djson').textContent);
$('#q').oninput=e=>{clearTimeout(timer);timer=setTimeout(()=>{S.q=e.target.value;load(true)},300)};
$('#rx').onclick=()=>{S.rx=!S.rx;$('#rx').classList.toggle('on',S.rx);load(true)};
const dt=(id,k)=>$(id).onchange=e=>{S[k]=e.target.value?String(Math.floor(Date.parse(e.target.value+':00Z')/1000)):'';load(true)};
dt('#from','from');dt('#to','to');
$('#reset').onclick=()=>{S.q='';S.rx=false;S.from=S.to='';for(const k in S.sel)S.sel[k]=[];$('#q').value='';$('#rx').classList.remove('on');$('#from').value=$('#to').value='';load(true)};
$('#csv').onclick=()=>{location.href='/api/export?'+qs({order:S.order})};
$('#prev').onclick=()=>{S.page--;load(false)};$('#next').onclick=()=>{S.page++;load(false)};
$('#size').onchange=e=>{S.size=+e.target.value;load(true)};
$('#th-ts').onclick=()=>{S.order=S.order==='asc'?'desc':'asc';$('#th-ts').textContent='Waktu (UTC) '+(S.order==='asc'?'↑':'↓');load(true)};
window.addEventListener('resize',drawHist);
renderPresets();load(true);
</script></body></html>
"""


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ndjson")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    nd = os.path.abspath(a.ndjson)
    if not os.path.isfile(nd):
        sys.exit(f"File tidak ditemukan: {nd}")
    db = nd + ".sqlite"
    if a.rebuild or not os.path.exists(db):
        print("[*] membangun indeks (sekali saja)...", file=sys.stderr)
        build_index(nd, db)
    H.db, H.nd = db, nd
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    url = f"http://127.0.0.1:{a.port}/"
    print(f"[+] buka {url}   (Ctrl+C untuk berhenti)", file=sys.stderr)
    if not a.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
