#!/usr/bin/env python3
"""ExamHub offline server. Needs only Python 3.8+ (no pip). Run: python3 server.py [port]
Data: examhub.db. Telegram (optional): set env BOT_TOKEN, and put the group chat id in CHAT_ID below.
  Linux/Mac: BOT_TOKEN=123:ABC python3 server.py      Windows (cmd): set BOT_TOKEN=123:ABC && python server.py"""
import html, json, os, re, socket, sqlite3, sys, threading, time, urllib.error, urllib.parse, urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
D = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
HOST = os.environ.get('HOST', '0.0.0.0')                      # di belakang nginx: HOST=127.0.0.1
DB_PATH = os.path.abspath(os.environ.get('EXAMHUB_DB') or os.path.join(D, 'examhub.db'))
try:
    db = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    db.execute('create table if not exists docs(c text, id text, d text, primary key(c,id))')
    db.execute('create table if not exists outbox(n integer primary key autoincrement, t text)')
    db.execute('create table if not exists health(x)'); db.commit()
except sqlite3.Error as e:
    try: import getpass; who = getpass.getuser()
    except Exception: who = '?'
    sys.exit(f"[ERROR] Tidak bisa membuka/menulis database: {e}\n  File : {DB_PATH}\n  User : {who}\n"
             f"  User ini harus punya izin TULIS ke file DAN foldernya (SQLite membuat file journal di folder yang sama).\n"
             f"  Contoh: sudo chown -R {who}: {os.path.dirname(DB_PATH)}   atau set EXAMHUB_DB=/path/yang/bisa/ditulis/examhub.db")
LK = threading.Lock(); OK = re.compile(r'^[A-Za-z0-9_.-]{1,40}$'); COLS = ('users', 'exams', 'attempts', 'ctf')
CHAT_ID = "-xx"   # <-- GANTI dengan chat id grup Telegram kamu (angka negatif)
TOKEN = os.environ.get('BOT_TOKEN', '').strip()                  # bot token: dari environment variable
CHAT = CHAT_ID if CHAT_ID != "-xx" else ''                 # placeholder belum diganti = Telegram nonaktif
esc = lambda x: html.escape(str(x))
passed = lambda c, t: c * 4 > t * 3          # lulus jika benar > 75%

def queue(text):                              # call while holding LK
    if TOKEN and CHAT: db.execute('insert into outbox(t) values(?)', (text,)); db.commit()

def attempt_msg(a):
    ok = passed(a['correct'], a['total']); s = int(a.get('secs', 0))
    return (f"{'✅' if ok else '❌'} <b>{esc(a.get('uname', '?'))}</b> selesai {'CTF' if a.get('kind') == 'ctf' else 'exam'} <b>{esc(a.get('etitle', '?'))}</b>\n"
            f"Skor: <b>{a['score']}</b> ({a['correct']}/{a['total']} benar)\nStatus: <b>{'LULUS' if ok else 'GAGAL'}</b>\nDurasi: {s // 60}m {s % 60}s")

def summary(eid):
    rows = [json.loads(d) for (d,) in db.execute("select d from docs where c='attempts'")]
    if eid: rows = [r for r in rows if r.get('eid') == eid]
    if not rows: return None
    n = len(rows); lu = sum(passed(r['correct'], r['total']) for r in rows); best = max(rows, key=lambda r: r['score'])
    return (f"📊 <b>Ringkasan {esc(rows[0]['etitle']) if eid else 'semua exam'}</b>\nTotal percobaan: {n}\n"
            f"Lulus: {lu} ({round(lu * 100 / n)}%) · Gagal: {n - lu}\nRata-rata skor: {sum(r['score'] for r in rows) / n:.1f}\n"
            f"Skor tertinggi: {best['score']} ({esc(best['uname'])})")

def send(t):
    req = urllib.request.Request(f'https://api.telegram.org/bot{TOKEN}/sendMessage',
        urllib.parse.urlencode({'chat_id': CHAT, 'text': t, 'parse_mode': 'HTML'}).encode())
    urllib.request.urlopen(req, timeout=15).read()

def worker():                                 # kirim antrean; kalau offline, coba lagi nanti
    while True:
        time.sleep(3)
        with LK: rows = db.execute('select n,t from outbox order by n limit 20').fetchall()
        for n, t in rows:
            try: send(t)
            except urllib.error.HTTPError as e:
                print('[telegram]', e.code, e.read()[:150])
                if e.code == 429: break
            except Exception: break
            with LK: db.execute('delete from outbox where n=?', (n,)); db.commit()

class Handler(BaseHTTPRequestHandler):
    def out(s, code, body=b'', ct='application/json'):
        s.send_response(code); s.send_header('Content-Type', ct + ('; charset=utf-8' if 'text' in ct else ''))
        s.send_header('Content-Length', str(len(body))); s.send_header('Cache-Control', 'no-store')
        s.end_headers(); s.wfile.write(body)
    def handle_m(s, m):
        try: s._h(m)
        except Exception as e:                    # jangan putus koneksi diam-diam: kirim pesan error yang jelas
            print('[error]', m, s.path, repr(e))
            try: s.out(500, f'Server error: {e}'.encode(), 'text/plain')
            except Exception: pass
    def _h(s, m):
        p = s.path.split('?')[0].strip('/').split('/')
        if 'api' in p: p = p[p.index('api'):]     # tahan terhadap prefix path dari reverse proxy (mis. /exam/api/...)
        if m == 'GET' and p[0] != 'api':
            return s.out(200, open(os.path.join(D, 'index.html'), 'rb').read(), 'text/html')
        if p == ['api', 'health'] and m == 'GET':      # tes baca + tulis database
            with LK: db.execute('insert into health values(1)'); db.execute('delete from health'); db.execute('select count(*) from docs').fetchone(); db.commit()
            return s.out(200, b'{"ok":true}')
        if p[:2] == ['api', 'summary'] and m == 'POST':
            if not (TOKEN and CHAT): return s.out(400, 'Telegram belum aktif: set env BOT_TOKEN dan isi CHAT_ID di server.py'.encode(), 'text/plain')
            with LK:
                t = summary(p[2] if len(p) > 2 and OK.match(p[2]) else None)
                if not t: return s.out(400, 'Belum ada data skor untuk diringkas'.encode(), 'text/plain')
                queue(t)
            return s.out(200, b'{}')
        if p[0] != 'api' or len(p) < 3 or p[2] not in COLS: return s.out(404)
        c = p[2]
        with LK:
            if p[1] == 'c' and m == 'GET':
                r = [{'id': i, 'data': json.loads(d)} for i, d in db.execute('select id,d from docs where c=?', (c,))]
                return s.out(200, json.dumps(r).encode())
            if p[1] != 'd' or len(p) != 4 or not OK.match(p[3]): return s.out(404)
            i = p[3]; row = db.execute('select d from docs where c=? and id=?', (c, i)).fetchone()
            if m == 'GET': return s.out(200, row[0].encode()) if row else s.out(404)
            if m == 'DELETE':
                db.execute('delete from docs where c=? and id=?', (c, i)); db.commit(); return s.out(200, b'{}')
            b = json.loads(s.rfile.read(int(s.headers.get('Content-Length', 0))) or '{}')
            if m == 'PATCH': b = {**(json.loads(row[0]) if row else {}), **b}
            if m == 'PUT' and c == 'attempts' and row is None:
                try:                          # hitung ulang skor di server, lalu antrekan notifikasi
                    det = b.get('det')
                    if isinstance(det, list) and det:
                        b['total'] = len(det); b['correct'] = sum(1 for x in det if x.get('u') == x.get('a'))
                        b['score'] = int(b['correct'] * 100 / b['total'] + .5)
                    queue(attempt_msg(b))
                except Exception as e: print('[attempt]', e)
            db.execute('insert or replace into docs values(?,?,?)', (c, i, json.dumps(b))); db.commit()
            s.out(200, b'{}')
    def do_GET(s): s.handle_m('GET')
    def do_PUT(s): s.handle_m('PUT')
    def do_POST(s): s.handle_m('POST')
    def do_PATCH(s): s.handle_m('PATCH')
    def do_DELETE(s): s.handle_m('DELETE')
    def log_message(s, *a): pass

def lan_ip():
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); t.connect(('10.255.255.255', 1)); ip = t.getsockname()[0]; t.close(); return ip
    except Exception: return '127.0.0.1'

threading.Thread(target=worker, daemon=True).start()
print(f"ExamHub running (database: {DB_PATH})\n  This computer : http://localhost:{PORT}\n  Other devices : http://{lan_ip()}:{PORT}\n  Admin portal  : add /#admin\n"
      f"  Telegram      : {'aktif' if TOKEN and CHAT else 'nonaktif — ' + ('env BOT_TOKEN belum diset' if not TOKEN else 'CHAT_ID di server.py belum diganti')}\nCtrl+C to stop.")
ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
