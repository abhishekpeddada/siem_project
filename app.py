#!/usr/bin/env python3
"""
Flask SIEM with YARA rule support.

- Put .yar files into ./rules/
- Logs go to ./logs/ (one event per line)
- POST /ingest to ingest current files
- POST /rules/reload to recompile YARA rules
"""
import os
import re
import json
import glob
import hashlib
import datetime
import yara
import requests

from flask import Flask, request, jsonify, render_template_string, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# --- config
load_dotenv()
STORAGE_PATH = os.getenv('STORAGE_PATH', './logs')
RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')
DB_PATH = os.path.join(os.path.dirname(__file__), 'siem.db')

# --- flask & db
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- models
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    raw = db.Column(db.Text, nullable=False, unique=False)
    timestamp = db.Column(db.DateTime, nullable=True)
    udm = db.Column(db.Text)  # json string
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Rule(db.Model):
    # optional DB mapping; YARA file-first approach doesn't rely on this
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    pattern = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    threshold = db.Column(db.Integer, default=1)
    window_seconds = db.Column(db.Integer, default=60)
    group_by = db.Column(db.String(100), nullable=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=True)
    signature = db.Column(db.String(128), unique=True, nullable=False)
    count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    sample_log_id = db.Column(db.Integer, db.ForeignKey('log.id'), nullable=True)
    notes = db.Column(db.Text)

class AlertLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alert.id'))
    log_id = db.Column(db.Integer, db.ForeignKey('log.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Playbook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    steps = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

db.create_all()

# --- utilities
def md5hex(s: str):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def parse_udm(raw: str):
    raw = raw.strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    # key=value pairs
    kvpairs = re.findall(r"(\w+)=([\"']?[^ \"]+[\"']?)", raw)
    if kvpairs:
        kv = {}
        for k,v in kvpairs:
            kv[k] = v.strip('"')
        return kv
    # syslog-ish
    m = re.match(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<rest>.*)$", raw)
    if m:
        return {"timestamp": m.group('ts'), "message": m.group('rest')}
    return {"message": raw}

# --- YARA rules
COMPILED_RULES = None

def compile_yara_rules():
    global COMPILED_RULES
    os.makedirs(RULES_DIR, exist_ok=True)
    rule_files = glob.glob(os.path.join(RULES_DIR, '*.yar')) + glob.glob(os.path.join(RULES_DIR, '*.yara'))
    if not rule_files:
        COMPILED_RULES = None
        app.logger.info("No YARA files found in rules/")
        return
    filedict = {f"r{idx}": path for idx, path in enumerate(rule_files)}
    try:
        COMPILED_RULES = yara.compile(filepaths=filedict)
        app.logger.info(f"Compiled {len(filedict)} yara files.")
    except yara.Error as e:
        COMPILED_RULES = None
        app.logger.error("YARA compile failed: %s", e)

compile_yara_rules()

@app.route('/rules/reload', methods=['POST'])
def reload_rules():
    compile_yara_rules()
    return jsonify({'ok': True})

# --- detection core using YARA
def apply_yara_rules_to_log(log: Log):
    global COMPILED_RULES
    if not COMPILED_RULES:
        return []
    matched = []
    now = datetime.datetime.utcnow()
    try:
        matches = COMPILED_RULES.match(data=log.raw)
    except Exception as e:
        app.logger.error("YARA match error: %s", e)
        return []
    for m in matches:
        rule_name = m.rule
        meta = getattr(m, 'meta', {}) or {}
        strings = getattr(m, 'strings', []) or []

        threshold = int(meta.get('threshold', 1))
        window = int(meta.get('window_seconds', 60))
        group_by_regex = meta.get('group_by_regex')

        sig = None
        # group_by_regex
        if group_by_regex:
            try:
                rg = re.compile(group_by_regex)
                mm = rg.search(log.raw)
                if mm:
                    sig = mm.group(1) if mm.groups() >= 1 else mm.group(0)
            except Exception:
                pass

        # fallback: try strings for IP/email
        if not sig:
            for sid, off, sval in strings:
                s = sval.decode('utf-8') if isinstance(sval, (bytes,bytearray)) else str(sval)
                ipm = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', s)
                if ipm:
                    sig = ipm.group(1); break
                em = re.search(r'([\w\.-]+@[\w\.-]+)', s)
                if em:
                    sig = em.group(1); break

        if threshold <= 1:
            signature_key = f"yara:{rule_name}|{sig or md5hex(log.raw)[:16]}"
            signature = md5hex(signature_key)
            alert = Alert.query.filter_by(signature=signature).first()
            if alert:
                alert.count += 1
                alert.last_seen = now
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id))
                db.session.commit()
            else:
                alert = Alert(rule_id=None, signature=signature, count=1,
                              first_seen=now, last_seen=now, sample_log_id=log.id)
                db.session.add(alert); db.session.commit()
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id)); db.session.commit()
            matched.append({'rule': rule_name, 'alert_id': alert.id})
            continue

        # threshold > 1: count recent matching logs
        window_start = now - datetime.timedelta(seconds=window)
        recent_q = Log.query.filter(Log.created_at >= window_start).order_by(Log.created_at.desc()).all()
        recent_count = 0
        for rl in recent_q:
            try:
                if COMPILED_RULES.match(data=rl.raw):
                    if sig:
                        if group_by_regex:
                            mm = re.search(group_by_regex, rl.raw)
                            if not mm or (mm.group(1) != sig):
                                continue
                        else:
                            if sig not in rl.raw:
                                continue
                    recent_count += 1
            except Exception:
                continue

        if recent_count >= threshold:
            signature_key = f"yara:{rule_name}|{sig or md5hex(log.raw)[:16]}"
            signature = md5hex(signature_key)
            alert = Alert.query.filter_by(signature=signature).first()
            if alert:
                alert.count += 1
                alert.last_seen = now
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id))
                db.session.commit()
            else:
                alert = Alert(rule_id=None, signature=signature, count=1,
                              first_seen=now, last_seen=now, sample_log_id=log.id)
                db.session.add(alert); db.session.commit()
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id)); db.session.commit()
            matched.append({'rule': rule_name, 'alert_id': alert.id, 'reason': f'{recent_count}/{threshold}'})
        else:
            matched.append({'rule': rule_name, 'alert_id': None, 'reason': f'waiting {recent_count}/{threshold}'})
    return matched

# --- ingestion
@app.route('/ingest', methods=['GET','POST'])
def ingest():
    if request.method == 'GET':
        files = []
        if os.path.isdir(STORAGE_PATH):
            files = os.listdir(STORAGE_PATH)
        return jsonify({'storage_path': STORAGE_PATH, 'file_count': len(files)})
    processed = 0
    os.makedirs(STORAGE_PATH, exist_ok=True)
    for fname in os.listdir(STORAGE_PATH):
        fpath = os.path.join(STORAGE_PATH, fname)
        if os.path.isfile(fpath):
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    raw = line.strip()
                    if not raw: continue
                    # skip exact duplicates
                    if Log.query.filter_by(raw=raw).first():
                        continue
                    udm = parse_udm(raw)
                    ts = None
                    if isinstance(udm, dict) and 'timestamp' in udm:
                        try:
                            ts = datetime.datetime.fromisoformat(udm['timestamp'])
                        except Exception:
                            # try common format
                            try:
                                ts = datetime.datetime.strptime(udm['timestamp'], '%Y-%m-%d %H:%M:%S')
                            except Exception:
                                ts = None
                    log = Log(raw=raw, timestamp=ts, udm=json.dumps(udm))
                    db.session.add(log)
                    db.session.commit()
                    # detection via YARA
                    apply_yara_rules_to_log(log)
                    processed += 1
    return jsonify({'processed': processed})

# --- UI templates (very small)
base_tpl = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <title>Flask SIEM</title>
</head>
<body>
<nav class="navbar navbar-dark bg-dark">
  <div class="container-fluid">
    <a class="navbar-brand" href="/">FlaskSIEM</a>
    <div>
      <a class="btn btn-sm btn-secondary" href="/rules/reload" onclick="event.preventDefault(); fetch('/rules/reload',{method:'POST'}).then(()=>location.reload())">Reload YARA</a>
      <a class="btn btn-sm btn-light" href="/ingest" onclick="event.preventDefault(); fetch('/ingest',{method:'POST'}).then(()=>location.reload())">Ingest</a>
    </div>
  </div>
</nav>
<div class="container mt-3">{{ content }}</div>
</body>
</html>
'''

@app.route('/')
def dashboard():
    alerts = Alert.query.order_by(Alert.last_seen.desc()).all()
    rows = ''
    for a in alerts:
        rows += f"<tr><td>{a.id}</td><td>{a.rule_id or 'YARA'}</td><td>{a.count}</td><td>{a.first_seen}</td><td>{a.last_seen}</td><td><a href='/alert/{a.id}'>View</a></td></tr>"
    content = f'''
    <h1>Alerts</h1>
    <table class="table table-striped"><thead><tr><th>ID</th><th>Rule</th><th>Count</th><th>First</th><th>Last</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table>
    '''
    return render_template_string(base_tpl, content=content)

@app.route('/alert/<int:alert_id>')
def alert_view(alert_id):
    a = Alert.query.get_or_404(alert_id)
    links = AlertLog.query.filter_by(alert_id=alert_id).order_by(AlertLog.created_at.desc()).limit(50).all()
    parts = ''
    for l in links:
        log = Log.query.get(l.log_id)
        udm_pre = ''
        try:
            udm_pre = json.dumps(json.loads(log.udm), indent=2)
        except Exception:
            udm_pre = str(log.udm)
        parts += f'<div class="card mb-2"><div class="card-body"><pre style="white-space:pre-wrap">{log.raw}</pre><details><summary>UDM</summary><pre>{udm_pre}</pre></details></div></div>'
    content = f'''
    <h2>Alert {a.id}</h2>
    <p><strong>Count:</strong> {a.count}</p>
    <p><a class="btn btn-primary" href="/analyze/{a.id}">Analyze with Google AI</a></p>
    <h3>Recent logs</h3>
    {parts}
    <h3>Notes</h3>
    <pre>{a.notes or ''}</pre>
    '''
    return render_template_string(base_tpl, content=content)

@app.route('/analyze/<int:alert_id>', methods=['GET'])
def analyze(alert_id):
    a = Alert.query.get_or_404(alert_id)
    links = AlertLog.query.filter_by(alert_id=alert_id).order_by(AlertLog.created_at.desc()).limit(5).all()
    texts = []
    for l in links:
        log = Log.query.get(l.log_id)
        texts.append(log.raw)
    prompt = "Analyze these logs and provide root cause, suggested next steps, and a short playbook:\n\n" + "\n\n".join(texts)

    if not GOOGLE_API_KEY:
        return "Google API key not configured. Set GOOGLE_API_KEY env var.", 400

    url = f"https://generativelanguage.googleapis.com/v1beta2/models/text-bison-001:generate?key={GOOGLE_API_KEY}"
    payload = {"prompt": {"text": prompt}, "temperature": 0.2, "maxOutputTokens": 512}
    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        output = ''
        if 'candidates' in data:
            output = '\n\n'.join([c.get('output','') for c in data['candidates']])
        elif 'output' in data:
            output = data['output']
        else:
            output = json.dumps(data, indent=2)
    except Exception as e:
        output = f"Error calling Google API: {e}"

    a.notes = (a.notes or '') + f"\n\n--- Analysis ({datetime.datetime.utcnow().isoformat()}):\n" + output
    db.session.commit()
    content = f"<h2>Analysis for Alert {a.id}</h2><pre>{output}</pre><p><a href='/alert/{a.id}'>Back</a></p>"
    return render_template_string(base_tpl, content=content)

@app.route('/logs')
def view_logs():
    q = request.args.get('q')
    if q:
        logs = Log.query.filter(Log.raw.contains(q)).order_by(Log.created_at.desc()).limit(200).all()
    else:
        logs = Log.query.order_by(Log.created_at.desc()).limit(200).all()
    rows = ''
    for l in logs:
        rows += f"<tr><td>{l.id}</td><td><pre style='white-space:pre-wrap'>{l.raw}</pre></td><td>{l.created_at}</td></tr>"
    content = f'''
    <h2>Logs</h2>
    <form class="mb-3"><input name="q" placeholder="search" class="form-control" value="{request.args.get('q','')}"></form>
    <table class="table"><thead><tr><th>ID</th><th>Raw</th><th>When</th></tr></thead><tbody>{rows}</tbody></table>
    '''
    return render_template_string(base_tpl, content=content)

@app.route('/playbooks', methods=['GET','POST'])
def playbooks():
    if request.method == 'POST':
        name = request.form.get('name')
        steps = request.form.get('steps')
        p = Playbook(name=name, steps=steps)
        db.session.add(p); db.session.commit()
        return redirect(url_for('playbooks'))
    pls = Playbook.query.order_by(Playbook.id.desc()).all()
    rows = ''
    for p in pls:
        rows += f"<tr><td>{p.id}</td><td>{p.name}</td><td><pre>{p.steps}</pre></td></tr>"
    content = f'''
    <h2>Playbooks</h2>
    <form method="post" class="mb-3">
      <input name="name" placeholder="Playbook name" class="form-control mb-2" required>
      <textarea name="steps" placeholder="Steps (one per line or JSON)" class="form-control mb-2"></textarea>
      <button class="btn btn-primary">Add</button>
    </form>
    <table class="table"><thead><tr><th>ID</th><th>Name</th><th>Steps</th></tr></thead><tbody>{rows}</tbody></table>
    '''
    return render_template_string(base_tpl, content=content)

@app.route('/api/rules', methods=['POST'])
def api_add_rule():
    data = request.json or {}
    name = data.get('name')
    pattern = data.get('pattern')
    description = data.get('description')
    if not name or not pattern:
        return jsonify({'error': 'name and pattern required'}), 400
    r = Rule(name=name, pattern=pattern)
    db.session.add(r); db.session.commit()
    return jsonify({'ok': True, 'id': r.id})

if __name__ == '__main__':
    os.makedirs(STORAGE_PATH, exist_ok=True)
    os.makedirs(RULES_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
