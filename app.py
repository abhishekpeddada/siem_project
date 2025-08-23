#!/usr/bin/env python3
"""
Flask SIEM single-file app — final fixed version.

- Put .yar/.yara files into ./rules/
- Put logs (one event per line) into ./logs/
- POST /rules/reload to compile rules
- POST /ingest to ingest log files
- POST /_reprocess_logs to re-run detection over stored logs
- GET /_rules_test_matches to inspect which rules matched which stored logs
- Dashboard at /
"""
import os
import re
import json
import glob
import hashlib
import datetime as dt
import yara
import requests
from dotenv import load_dotenv

from flask import Flask, request, jsonify, render_template_string, make_response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

# --------------------
# Config
# --------------------
load_dotenv()
STORAGE_PATH = os.getenv('STORAGE_PATH', './logs')
RULES_DIR = os.path.join(os.path.dirname(__file__), 'rules')
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '') 
DB_PATH = os.path.join(os.path.dirname(__file__), 'siem.db')

# --------------------
# Flask & DB
# --------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --------------------
# DB Models & helpers
# --------------------
def now_utc():
    return dt.datetime.now(dt.timezone.utc)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    raw = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=True)
    udm = db.Column(db.Text)  # JSON string
    created_at = db.Column(db.DateTime, default=now_utc)

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    pattern = db.Column(db.Text)
    enabled = db.Column(db.Boolean, default=True)
    threshold = db.Column(db.Integer, default=1)
    window_seconds = db.Column(db.Integer, default=60)
    group_by = db.Column(db.String(100), nullable=True)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # yara_rule_name is a better way to store the source of the alert.
    yara_rule_name = db.Column(db.String(255), nullable=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('rule.id'), nullable=True)
    signature = db.Column(db.String(128), unique=True, nullable=False)
    count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.DateTime, default=now_utc)
    last_seen = db.Column(db.DateTime, default=now_utc)
    sample_log_id = db.Column(db.Integer, db.ForeignKey('log.id'), nullable=True)
    notes = db.Column(db.Text)

class AlertLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey('alert.id'))
    log_id = db.Column(db.Integer, db.ForeignKey('log.id'))
    created_at = db.Column(db.DateTime, default=now_utc)

class Playbook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    steps = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=now_utc)

with app.app_context():
    db.create_all()

# --------------------
# Utilities
# --------------------
def md5hex(s: str):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def parse_udm(raw: str):
    """
    Try to parse raw into structured UDM:
      - JSON if possible
      - key=value pairs
      - leading timestamp pattern "YYYY-MM-DD HH:MM:SS rest..."
      - fall back to message
    """
    raw = raw.strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    kvpairs = re.findall(r"(\w+)=([\"']?[^ \"]+[\"']?)", raw)
    if kvpairs:
        kv = {}
        for k, v in kvpairs:
            kv[k] = v.strip('"').strip("'")
        return kv
    m = re.match(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<rest>.*)$", raw)
    if m:
        return {"timestamp": m.group('ts'), "message": m.group('rest')}
    return {"message": raw}

# --------------------
# YARA management
# --------------------
COMPILED_RULES = None
LAST_YARA_ERROR = None

def compile_yara_rules():
    global COMPILED_RULES, LAST_YARA_ERROR
    os.makedirs(RULES_DIR, exist_ok=True)
    rule_files = sorted(glob.glob(os.path.join(RULES_DIR, '*.yar')) + glob.glob(os.path.join(RULES_DIR, '*.yara')))
    if not rule_files:
        COMPILED_RULES = None
        LAST_YARA_ERROR = None
        app.logger.info("No YARA files found in rules/")
        return
    filedict = {f"r{idx}": path for idx, path in enumerate(rule_files)}
    try:
        COMPILED_RULES = yara.compile(filepaths=filedict)
        LAST_YARA_ERROR = None
        app.logger.info("Compiled %d yara files.", len(filedict))
    except yara.Error as e:
        COMPILED_RULES = None
        LAST_YARA_ERROR = str(e)
        app.logger.error("YARA compile failed: %s", e)

compile_yara_rules()

@app.route('/rules/reload', methods=['POST'])
def reload_rules():
    compile_yara_rules()
    return jsonify({'ok': True})

# --------------------
# Detection core — event-time-aware & robust
# --------------------
def apply_yara_rules_to_log(log: Log):
    """
    Apply compiled YARA rules to a Log record.

    Key points:
    - Use event_time = log.timestamp if available else log.created_at (prefer event time)
    - Count recent events in [event_time - window, event_time]
    - Robust to yara.StringMatch or tuple shapes
    """
    global COMPILED_RULES
    if not COMPILED_RULES:
        return []

    matched = []
    try:
        matches = COMPILED_RULES.match(data=log.raw)
    except Exception as e:
        app.logger.error("YARA match error: %s", e)
        return []

    # determine event_time for window calculation; make timezone-aware
    event_time = log.timestamp or log.created_at or dt.datetime.now(dt.timezone.utc)
    if isinstance(event_time, dt.datetime) and event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=dt.timezone.utc)

    for m in matches:
        rule_name = m.rule
        meta = getattr(m, 'meta', {}) or {}
        strings = getattr(m, 'strings', []) or []

        try:
            threshold = int(meta.get('threshold', 1))
        except Exception:
            threshold = 1
        try:
            window = int(meta.get('window_seconds', 60))
        except Exception:
            window = 60
        group_by_regex = meta.get('group_by_regex')

        # derive grouping sig
        sig = None
        if group_by_regex:
            try:
                rg = re.compile(group_by_regex)
                mm = rg.search(log.raw)
                if mm:
                    sig = mm.group(1) if len(mm.groups()) >= 1 else mm.group(0)
            except Exception as e:
                app.logger.debug("group_by_regex eval error for %s: %s", rule_name, e)
                sig = None

        if not sig and strings:
            for s in strings:
                sval = None
                if isinstance(s, (tuple, list)) and len(s) >= 3:
                    sval = s[2]
                else:
                    sval = getattr(s, 'data', None) or getattr(s, 'value', None) or s
                try:
                    stext = sval.decode('utf-8') if isinstance(sval, (bytes, bytearray)) else str(sval)
                except Exception:
                    stext = str(sval)
                ipm = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', stext)
                if ipm:
                    sig = ipm.group(1); break
                em = re.search(r'([\w\.-]+@[\w\.-]+)', stext)
                if em:
                    sig = em.group(1); break

        if not sig:
            try:
                udm = json.loads(log.udm) if log.udm else {}
                if isinstance(udm, dict):
                    for k in ('src_ip', 'ip', 'user', 'username', 'from', 'email'):
                        if k in udm:
                            sig = udm.get(k)
                            break
            except Exception:
                pass

        if not sig:
            sig = md5hex(log.raw)[:16]

        signature_key = f"yara:{rule_name}|{sig}"
        signature = md5hex(signature_key)

        # immediate alert for threshold <= 1
        now = dt.datetime.now(dt.timezone.utc)
        if threshold <= 1:
            alert = Alert.query.filter_by(signature=signature).first()
            if alert:
                alert.count += 1
                alert.last_seen = now
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id))
                db.session.commit()
            else:
                alert = Alert(
                    yara_rule_name=rule_name, # <-- ADDED
                    rule_id=None,
                    signature=signature,
                    count=1,
                    first_seen=now, last_seen=now, sample_log_id=log.id)
                db.session.add(alert); db.session.commit()
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id)); db.session.commit()
            matched.append({'rule': rule_name, 'alert_id': alert.id, 'reason': 'single'})
            continue

        # sliding-window: window relative to event_time
        window_start = event_time - dt.timedelta(seconds=window)

        # collect recent logs in the [window_start, event_time] range
        recent_logs = []
        try:
            recent_logs = Log.query.filter(
                Log.timestamp != None,
                Log.timestamp >= window_start,
                Log.timestamp <= event_time
            ).order_by(Log.timestamp.desc()).all()
        except Exception:
            recent_logs = []

        try:
            created_q = Log.query.filter(
                Log.timestamp == None,
                Log.created_at >= window_start,
                Log.created_at <= event_time
            ).order_by(Log.created_at.desc()).all()
            seen_ids = set(l.id for l in recent_logs)
            for rl in created_q:
                if rl.id not in seen_ids:
                    recent_logs.append(rl)
                    seen_ids.add(rl.id)
        except Exception:
            pass

        if log.id not in [r.id for r in recent_logs]:
            recent_logs.insert(0, log)

        recent_count = 0
        for rl in recent_logs:
            try:
                rl_matches = COMPILED_RULES.match(data=rl.raw)
                if not rl_matches:
                    continue
                matched_names = [mm.rule for mm in rl_matches]
                if rule_name not in matched_names:
                    continue

                if group_by_regex:
                    mm2 = re.search(group_by_regex, rl.raw)
                    if not mm2:
                        continue
                    val = mm2.group(1) if len(mm2.groups()) >= 1 else mm2.group(0)
                    if val != sig:
                        continue
                else:
                    if sig not in rl.raw and sig != md5hex(rl.raw)[:16]:
                        continue

                recent_count += 1
            except Exception:
                continue

        if recent_count >= threshold:
            alert = Alert.query.filter_by(signature=signature).first()
            if alert:
                alert.count = max(alert.count, recent_count)
                alert.last_seen = event_time if isinstance(event_time, dt.datetime) else now
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id))
                db.session.commit()
            else:
                alert = Alert(
                    yara_rule_name=rule_name, # <-- ADDED
                    rule_id=None,
                    signature=signature,
                    count=recent_count,
                    first_seen=event_time if isinstance(event_time, dt.datetime) else now,
                    last_seen=event_time if isinstance(event_time, dt.datetime) else now,
                    sample_log_id=log.id)
                db.session.add(alert); db.session.commit()
                db.session.add(AlertLog(alert_id=alert.id, log_id=log.id)); db.session.commit()
            matched.append({'rule': rule_name, 'alert_id': alert.id, 'reason': f'{recent_count}/{threshold}'})
        else:
            matched.append({'rule': rule_name, 'alert_id': None, 'reason': f'waiting {recent_count}/{threshold}'})

    return matched

# --------------------
# Ingest endpoint
# --------------------
@app.route('/ingest', methods=['GET', 'POST'])
def ingest():
    if request.method == 'GET':
        files = []
        if os.path.isdir(STORAGE_PATH):
            files = os.listdir(STORAGE_PATH)
        return jsonify({'storage_path': STORAGE_PATH, 'file_count': len(files)})

    processed = 0
    os.makedirs(STORAGE_PATH, exist_ok=True)
    for fname in sorted(os.listdir(STORAGE_PATH)):
        fpath = os.path.join(STORAGE_PATH, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    raw = line.strip()
                    if not raw:
                        continue
                    if Log.query.filter_by(raw=raw).first():
                        continue
                    udm = parse_udm(raw)
                    ts = None
                    if isinstance(udm, dict) and 'timestamp' in udm:
                        try:
                            ts = dt.datetime.fromisoformat(udm['timestamp'])
                        except Exception:
                            try:
                                ts = dt.datetime.strptime(udm['timestamp'], '%Y-%m-%d %H:%M:%S')
                            except Exception:
                                ts = None
                    log = Log(raw=raw, timestamp=ts, udm=json.dumps(udm))
                    db.session.add(log)
                    db.session.commit()
                    apply_yara_rules_to_log(log)
                    processed += 1
        except Exception as e:
            app.logger.error("Error reading file %s: %s", fpath, e)
            continue

    return jsonify({'processed': processed})

# --------------------
# Debug/status & utilities
# --------------------
@app.route('/_debug_status')
def debug_status():
    yar_count = len(glob.glob(os.path.join(RULES_DIR, '*.yar'))) + len(glob.glob(os.path.join(RULES_DIR, '*.yara')))
    logs_count = 0
    if os.path.isdir(STORAGE_PATH):
        for f in os.listdir(STORAGE_PATH):
            p = os.path.join(STORAGE_PATH, f)
            if os.path.isfile(p):
                try:
                    with open(p, 'r', errors='ignore') as fh:
                        logs_count += sum(1 for _ in fh)
                except Exception:
                    pass
    alerts_count = Alert.query.count()
    return jsonify({
        "yara_compiled": bool(COMPILED_RULES),
        "yar_files": yar_count,
        "logs_lines": logs_count,
        "alerts": alerts_count,
        "last_yara_error": LAST_YARA_ERROR
    })

@app.route('/_rules_test_matches')
def rules_test_matches():
    if not COMPILED_RULES:
        return jsonify({"error": "No compiled YARA rules"}), 500
    out = []
    logs = Log.query.order_by(Log.created_at.asc()).all()
    for log in logs:
        entry = {"log_id": log.id, "raw": log.raw, "matches": []}
        try:
            matches = COMPILED_RULES.match(data=log.raw)
        except Exception as e:
            entry["error"] = f"YARA match error: {e}"
            out.append(entry)
            continue
        for m in matches:
            meta = getattr(m, "meta", {}) or {}
            strings = getattr(m, "strings", []) or []
            group_by_regex = meta.get("group_by_regex")
            sig = None
            sig_error = None
            if group_by_regex:
                try:
                    rg = re.compile(group_by_regex)
                    mm = rg.search(log.raw)
                    if mm:
                        sig = mm.group(1) if len(mm.groups()) >= 1 else mm.group(0)
                except Exception as e:
                    sig_error = str(e)
            if not sig and strings:
                for s in strings:
                    sval = None
                    if isinstance(s, (tuple, list)) and len(s) >= 3:
                        sval = s[2]
                    else:
                        sval = getattr(s, "data", None) or getattr(s, "value", None) or s
                    try:
                        stext = sval.decode("utf-8") if isinstance(sval, (bytes, bytearray)) else str(sval)
                    except Exception:
                        stext = str(sval)
                    ipm = re.search(r'([0-9]{1,3}(?:\.[0-9]{1,3}){3})', stext)
                    if ipm:
                        sig = ipm.group(1); break
                    em = re.search(r'([\w\.-]+@[\w\.-]+)', stext)
                    if em:
                        sig = em.group(1); break
            preview = []
            for s in strings:
                try:
                    if isinstance(s, (tuple, list)) and len(s) >= 3:
                        val = s[2]
                    else:
                        val = getattr(s, "data", None) or getattr(s, "value", None) or s
                    if isinstance(val, (bytes, bytearray)):
                        preview.append(val.decode('utf-8', errors='replace'))
                    else:
                        preview.append(str(val))
                except Exception:
                    preview.append(str(s))
            entry["matches"].append({
                "rule": m.rule,
                "meta": meta,
                "strings_preview": preview,
                "group_by_regex": group_by_regex,
                "derived_sig": sig,
                "sig_error": sig_error
            })
        out.append(entry)
    return jsonify({"results": out})

@app.route('/_reprocess_logs', methods=['POST'])
def reprocess_logs():
    count = 0
    logs = Log.query.order_by(Log.created_at.asc()).all()
    for lg in logs:
        try:
            res = apply_yara_rules_to_log(lg)
            if res:
                count += 1
        except Exception as e:
            app.logger.error("Error reprocessing log %s: %s", lg.id, e)
            continue
    return jsonify({"reprocessed_logs": len(logs), "affected_logs": count})

# --------------------
# UI (dashboard, alerts, logs, playbooks)
# --------------------
base_tpl = '''
<!doctype html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Flask SIEM</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-dark bg-dark mb-3">
            <div class="container-fluid">
                <a class="navbar-brand" href="/">AutoSecOps</a>
                <div>
                    <button id="reload" class="btn btn-sm btn-secondary">Reload YARA</button>
                    <button id="ingest" class="btn btn-sm btn-light">Ingest</button>
                </div>
            </div>
        </nav>
        <div class="container">{{ content|safe }}</div>
        <script>
            document.getElementById('reload').addEventListener('click', ()=> {
                fetch('/rules/reload', {method:'POST'}).then(()=>location.reload());
            });
            document.getElementById('ingest').addEventListener('click', ()=> {
                fetch('/ingest', {method:'POST'}).then(()=>location.reload());
            });
        </script>
    </body>
</html>
'''

@app.route('/')
def dashboard():
    alerts = Alert.query.order_by(Alert.last_seen.desc()).all()
    rows = ''
    for a in alerts:
        # Use yara_rule_name if available, otherwise fallback
        rule_name = a.yara_rule_name if a.yara_rule_name else (f'Rule ID {a.rule_id}' if a.rule_id else 'N/A')
        rows += f"<tr><td>{a.id}</td><td>{rule_name}</td><td>{a.count}</td><td>{a.first_seen}</td><td>{a.last_seen}</td><td><a href='/alert/{a.id}'>View</a></td></tr>"
    content = f'''
    <h1>Alerts</h1>
    <table class="table table-striped"><thead><tr><th>ID</th><th>Rule</th><th>Count</th><th>First</th><th>Last</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table>
    '''
    rendered = render_template_string(base_tpl, content=content)
    return make_response(rendered, 200, {'Content-Type': 'text/html; charset=utf-8'})

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
    <p><strong>Rule:</strong> {a.yara_rule_name or a.rule_id or 'N/A'}</p>
    <p><strong>Count:</strong> {a.count}</p>
    <p><a class="btn btn-primary" href="/analyze/{a.id}">Analyze with Google AI</a></p>
    <h3>Recent logs</h3>
    {parts}
    <h3>Notes</h3>
    <pre>{a.notes or ''}</pre>
    '''
    rendered = render_template_string(base_tpl, content=content)
    return make_response(rendered, 200, {'Content-Type': 'text/html; charset=utf-8'})

@app.route('/analyze/<int:alert_id>', methods=['GET'])
def analyze(alert_id):
    a = Alert.query.get_or_404(alert_id)
    links = AlertLog.query.filter_by(alert_id=alert_id).order_by(AlertLog.created_at.desc()).limit(5).all()
    texts = []
    for l in links:
        log = Log.query.get(l.log_id)
        texts.append(log.raw)

    predefined_prompt = """
    Assume you are a seasoned Cybersecurity Analyst. Analyze the logs provided and deliver a professional incident report in the following structure:

    Observations:
    Identify suspicious or notable activities, abnormal patterns, or policy violations from the logs.
    Highlight user accounts, IP addresses, devices, or applications involved.

    Impact Assessment:
    Explain the potential or confirmed security risks of the observed activity (e.g., data exfiltration, privilege escalation, lateral movement, external exposure).
    Clarify whether this is a critical, high, medium, or low severity issue.

    Recommendations:
    Provide clear, actionable security measures (technical and procedural) to mitigate or prevent similar events.
    Mention immediate containment steps if needed.

    Summary (Highlights):
    Bullet-point the major red flags and key takeaways that stakeholders must pay attention to.
    Keep it concise, executive-ready, and suitable for SOC handover reports.
    """

    # Combine the predefined prompt with the log data
    prompt = predefined_prompt + "\n\nLogs to analyze:\n" + "\n".join(texts)

    if not GOOGLE_API_KEY:
        return "Google API key not configured. Set GOOGLE_API_KEY env var.", 400

    # 🛠️ FIXED: Updated to the new API endpoint and model for Gemini 1.5 Flash.
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={GOOGLE_API_KEY}"
    
    # 🛠️ FIXED: The payload structure is the same as gemini-pro.
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 512
        }
    }
    
    try:
        r = requests.post(url, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        
        output = ''
        if 'candidates' in data and data['candidates']:
            first_candidate = data['candidates'][0]
            if 'content' in first_candidate and 'parts' in first_candidate['content']:
                output = '\n\n'.join([part.get('text', '') for part in first_candidate['content']['parts']])
        
        if not output:
            output = json.dumps(data, indent=2)

    except Exception as e:
        output = f"Error calling Google API: {e}"

    a.notes = (a.notes or '') + f"\n\n--- Analysis ({dt.datetime.now(dt.timezone.utc).isoformat()}):\n" + output
    db.session.commit()
    content = f"<h2>Analysis for Alert {a.id}</h2><pre>{output}</pre><p><a href='/alert/{a.id}'>Back</a></p>"
    rendered = render_template_string(base_tpl, content=content)
    return make_response(rendered, 200, {'Content-Type': 'text/html; charset=utf-8'})

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
    rendered = render_template_string(base_tpl, content=content)
    return make_response(rendered, 200, {'Content-Type': 'text/html; charset=utf-8'})

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
    rendered = render_template_string(base_tpl, content=content)
    return make_response(rendered, 200, {'Content-Type': 'text/html; charset=utf-8'})

@app.route('/api/rules', methods=['POST'])
def api_add_rule():
    data = request.json or {}
    name = data.get('name')
    pattern = data.get('pattern')
    if not name or not pattern:
        return jsonify({'error': 'name and pattern required'}), 400
    r = Rule(name=name, pattern=pattern)
    db.session.add(r); db.session.commit()
    return jsonify({'ok': True, 'id': r.id})

# --------------------
# Run
# --------------------
if __name__ == '__main__':
    os.makedirs(STORAGE_PATH, exist_ok=True)
    os.makedirs(RULES_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
