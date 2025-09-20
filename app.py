import os
import json
import sys
import requests
import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import google.generativeai as genai
from dotenv import load_dotenv
from typing import Any, Mapping, Optional, Sequence, Tuple
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import re

from list_rules import get_all_rules_by_ids
from list_detections import get_detections_for_rule
from common import chronicle_auth
from common import regions

load_dotenv()

app = Flask(__name__)

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure Gemini AI
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

CHRONICLE_CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "nfr4-backstory.json")
CHRONICLE_REGION = os.getenv("CHRONICLE_REGION", "us")
UDM_API_BASE_URL = "https://backstory.googleapis.com"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Monitored rule IDs
MONITORED_RULE_IDS = [
    "ru_41baf103-99d9-46cf-8bd7-d2bb3841f8f2",
    "ru_67b85d9f-b743-4ab5-84bc-b4004b2f133c",
    "ru_545584c3-3a45-4b9b-a1bb-dcea39f3bfdb",
    "ru_828e8fe8-d4ee-49cf-a934-ae3e0bcf037a"
]

# --- Global Rule Metadata Cache ---
RULE_METADATA_CACHE = {}

# --- Database Models ---
class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    correlation_key = db.Column(db.String(255), nullable=True, unique=False)
    detection_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    detections = db.relationship('IncidentDetection', backref='incident', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'created_at': self.created_at.isoformat(),
        }

class IncidentDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    detection_id = db.Column(db.String(255), nullable=False, unique=True)
    raw_data = db.Column(db.Text, nullable=False)
    
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'incident_id': self.incident_id,
            'sender': self.sender,
            'message': self.message,
            'timestamp': self.timestamp.isoformat()
        }


def format_to_chronicle_time(dt_str: str) -> Optional[str]:
    """Converts a datetime-local string to a UTC ISO 8601 string."""
    if not dt_str:
        return None
    try:
        dt_obj = datetime.datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")
        utc_dt = dt_obj.replace(tzinfo=datetime.timezone.utc)
        return utc_dt.isoformat(timespec='seconds').replace('+00:00', 'Z')
    except ValueError:
        return None


def real_udm_search(query: str, start_time: datetime.datetime, end_time: datetime.datetime, limit: int) -> Mapping[str, Any]:
    """Performs a UDM search against the real API."""
    if not os.path.exists(CHRONICLE_CREDENTIALS_FILE):
        raise FileNotFoundError(f"Chronicle credentials file not found at path: {CHRONICLE_CREDENTIALS_FILE}.")
    
    try:
        http_session = chronicle_auth.initialize_http_session(CHRONICLE_CREDENTIALS_FILE)
    except Exception as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        raise Exception(f"Authentication failed: {e}")
        
    region = "us"
    api_url = regions.url(UDM_API_BASE_URL, region)
    url = f"{api_url}/v1/events:udmSearch"
    
    s = start_time.astimezone(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    e = end_time.astimezone(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    
    params = {
        "query": query,
        "time_range.start_time": s,
        "time_range.end_time": e,
        "limit": limit
    }
    
    response = http_session.request("GET", url, params=params)
    response.raise_for_status()
    return response.json()

def extract_user_id(log_data: dict) -> Optional[str]:
    """Safely extracts a user ID from nested UDM log data."""
    if not log_data or not isinstance(log_data, dict):
        return None
    
    principal_user = log_data.get('principal', {}).get('user', {})
    target_user = log_data.get('target', {}).get('user', {})
    
    if principal_user and 'userid' in principal_user and principal_user['userid']:
        return principal_user['userid']
    
    if target_user and 'userid' in target_user and target_user['userid']:
        return target_user['userid']

    return None

def extract_ips(log_data: dict) -> set:
    """Safely extracts all unique IP addresses from nested UDM log data."""
    ips = set()
    if not log_data or not isinstance(log_data, dict):
        return ips
    
    ip_lists = [
        log_data.get('principal', {}).get('asset', {}).get('ip', []),
        log_data.get('principal', {}).get('ip', []),
        log_data.get('target', {}).get('ip', []),
    ]

    for ip_list in ip_lists:
        ips.update(ip_list)
    
    return ips

def extract_domains(log_data: dict) -> set:
    """Safely extracts domains from nested UDM log data."""
    domains = set()
    if not log_data or not isinstance(log_data, dict):
        return domains
    
    domains.update(log_data.get('network', {}).get('dns', {}).get('questions', [{}])[0].get('name', []))
    domains.update(log_data.get('network', {}).get('http', {}).get('host', []))
    
    return domains

def extract_files(log_data: dict) -> set:
    """Safely extracts file hashes from nested UDM log data."""
    files = set()
    if not log_data or not isinstance(log_data, dict):
        return files

    file_objects = [log_data.get('principal', {}).get('file'), log_data.get('target', {}).get('file')]
    for file_obj in file_objects:
        if file_obj and isinstance(file_obj, dict):
            files.update(file_obj.get('sha256', []))
            files.update(file_obj.get('md5', []))
            files.update(file_obj.get('sha1', []))
    
    return files

def extract_urls(log_data: dict) -> set:
    """Safely extracts URLs from nested UDM log data."""
    urls = set()
    if not log_data or not isinstance(log_data, dict):
        return urls
    
    urls.update(log_data.get('network', {}).get('http', {}).get('url', []))
    return urls


def extract_ips_from_udm_logs(logs) -> set:
    """Extracts all unique IPs from a list of UDM logs or a single log."""
    ips = set()
    
    if not logs:
        return ips
    
    if isinstance(logs, dict):
        event = logs.get('events', [{}])[0]
        ips.update(extract_ips(event))
    elif isinstance(logs, list):
        for log in logs:
            if isinstance(log, dict) and 'principal' in log:
                ips.update(extract_ips(log))
            elif isinstance(log, dict) and 'references' in log:
                event = log.get('references', [{}])[0].get('event', {})
                ips.update(extract_ips(event))
    
    return ips

def get_virustotal_report(indicator: str) -> Optional[dict]:
    """Fetches threat intelligence for an indicator from VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        print("VirusTotal API key not found. Skipping threat intel.")
        return None
        
    vt_url = "https://www.virustotal.com/api/v3/"
    endpoint = ""
    
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        endpoint = "ip_addresses/"
    elif re.match(r"^[a-f0-9]{64}$", indicator):
        endpoint = "files/"
    elif re.match(r"^[a-f0-9]{40}$", indicator):
        endpoint = "files/"
    elif re.match(r"^[a-f0-9]{32}$", indicator):
        endpoint = "files/"
    elif "." in indicator:
        endpoint = "domains/"
    elif "http" in indicator:
        import base64
        encoded_url = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        endpoint = f"urls/{encoded_url}"
    else:
        return None
        
    url = f"{vt_url}{endpoint}{indicator}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        # Correctly navigate the JSON response
        report_data = response.json().get("data")
        if report_data and isinstance(report_data, dict):
            # The stats are nested under 'attributes'
            return report_data.get('attributes')
        return None
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error fetching VirusTotal data for {indicator}: {e.response.text}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An unexpected error occurred during VirusTotal query for {indicator}: {e}", file=sys.stderr)
        return None

def generate_incident_title(raw_logs: str) -> str:
    """Generates a descriptive title for an incident using Gemini AI."""
    title_prompt = (
        f"Generate a concise and descriptive title (max 10 words) for a security incident based on the following raw logs. "
        f"Do not include the word 'incident' in the title. Focus on the core event and affected entities."
        f"Logs:\n\n{raw_logs}"
    )

    headers = {"Content-Type": "application/json"}
    payload = {
        "contents": [{"parts": [{"text": title_prompt}]}],
        "system_instruction": {"parts": [{"text": "You are an AI assistant that generates concise security incident titles."}]}
    }

    try:
        response = requests.post(f"{GEMINI_API_URL}?key={GEMINI_API_KEY}", headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        title = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'Uncategorized Detections').strip()
        if title.startswith('"') and title.endswith('"'):
            title = title[1:-1]
        return title
    except Exception as e:
        print(f"Error generating title with Gemini: {e}", file=sys.stderr)
        return "Uncategorized Detections"


def correlate_detections_into_incidents(detections):
    """Correlates new detections and groups them into incidents based on user ID and same date."""
    
    # In-memory dictionary to group detections before writing to DB
    groups = {}
    
    for det in detections:
        log_data = det.get('collectionElements', [{}])[0].get('references', [{}])[0].get('event', {})
        
        user_id = extract_user_id(log_data)
        
        try:
            detection_timestamp = datetime.datetime.fromisoformat(det.get('detectionTime', '').replace('Z', '+00:00'))
            detection_date = detection_timestamp.date()
        except (ValueError, TypeError):
            detection_date = datetime.date.today()

        if user_id:
            correlation_key = user_id
        else:
            correlation_key = det.get('id')
        
        correlation_tuple = (correlation_key, detection_date)
        
        if correlation_tuple not in groups:
            groups[correlation_tuple] = []
        
        groups[correlation_tuple].append(det)

    for key, group_detections in groups.items():
        correlation_key, detection_date = key
        
        existing_incident = Incident.query.filter_by(
            correlation_key=correlation_key,
            detection_date=detection_date
        ).first()

        if existing_incident:
            for det in group_detections:
                if not IncidentDetection.query.filter_by(detection_id=det.get('id')).first():
                    incident_detection = IncidentDetection(
                        incident_id=existing_incident.id,
                        detection_id=det.get('id'),
                        raw_data=json.dumps(det)
                    )
                    db.session.add(incident_detection)
        else:
            raw_log_string = json.dumps([det.get('collectionElements') for det in group_detections], indent=2)
            generated_title = "Incident: " + generate_incident_title(raw_log_string)
            
            new_incident = Incident(
                title=generated_title,
                correlation_key=correlation_key,
                detection_date=detection_date
            )
            db.session.add(new_incident)
            db.session.flush()
            
            for det in group_detections:
                incident_detection = IncidentDetection(
                    incident_id=new_incident.id,
                    detection_id=det.get('id'),
                    raw_data=json.dumps(det)
                )
                db.session.add(incident_detection)
    
    db.session.commit()
    return

@app.route("/")
def dashboard():
    """Renders the main dashboard, listing all incidents."""
    try:
        start_time_str = request.args.get("start_time")
        end_time_str = request.args.get("end_time")
        
        if not start_time_str or not end_time_str:
            end_time_obj = datetime.datetime.now(datetime.timezone.utc)
            start_time_obj = end_time_obj - datetime.timedelta(hours=24)
            start_time_str = start_time_obj.strftime("%Y-%m-%dT%H:%M")
            end_time_str = end_time_obj.strftime("%Y-%m-%dT%H:%M")
        
        start_time_iso = format_to_chronicle_time(start_time_str)
        end_time_iso = format_to_chronicle_time(end_time_str)

        all_new_detections = []
        for version_id in MONITORED_RULE_IDS:
            detections, _ = get_detections_for_rule(
                version_id=version_id,
                start_time=start_time_iso,
                end_time=end_time_iso,
                list_basis="DETECTION_TIME",
                alert_state="ALERTING",
                credentials_file=CHRONICLE_CREDENTIALS_FILE,
                region=CHRONICLE_REGION
            )
            all_new_detections.extend(detections)
        
        correlate_detections_into_incidents(all_new_detections)

        incidents = Incident.query.order_by(Incident.created_at.desc()).all()
        return render_template(
            "dashboard.html", 
            incidents=incidents, 
            start_time=start_time_str, 
            end_time=end_time_str
        )
    except Exception as e:
        return f"An error occurred: {e}", 500

@app.route("/incidents/<int:incident_id>")
def incident_details(incident_id):
    """Renders the details page for a specific incident."""
    incident = Incident.query.get_or_404(incident_id)
    detections_raw = [json.loads(d.raw_data) for d in incident.detections]
    
    return render_template(
        "incident_details.html",
        incident=incident,
        detections=detections_raw
    )
    
@app.route("/udm_search")
def udm_search_page():
    """Renders the UDM search page."""
    return render_template("udm_search.html")

@app.route("/api/udm_search", methods=["POST"])
def api_udm_search():
    """Handles the UDM search request and returns raw logs."""
    try:
        data = request.json
        query = data.get("query")
        start_time_str = data.get("start_time")
        end_time_str = data.get("end_time")
        limit = int(data.get("limit", 100))

        if not all([query, start_time_str, end_time_str]):
            return jsonify({"error": "Missing required fields"}), 400
        
        start_time_dt = datetime.datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
        end_time_dt = datetime.datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
        
        if start_time_dt >= end_time_dt:
            return jsonify({"error": "Invalid date or time range."}), 400

        results = real_udm_search(query, start_time_dt, end_time_dt, limit)
        return jsonify({"logs": results})
    except Exception as e:
        return jsonify({"error": f"UDM Search failed: {str(e)}"}), 500

@app.route("/api/chat", methods=["POST"])
def chat():
    """Handles the Gemini chat request for log analysis."""
    try:
        data = request.json
        prompt = data.get("prompt")
        incident_id = data.get("incident_id")
        logs = data.get("logs")
        
        if not prompt:
            return jsonify({"error": "Prompt is required"}), 400

        chat_history = []
        all_logs_string = ""
        all_ips = set()
        all_domains = set()
        all_hashes = set()
        all_urls = set()
        
        if incident_id:
            incident = Incident.query.get_or_404(incident_id)
            for detection_link in incident.detections:
                raw_log_data = json.loads(detection_link.raw_data)
                all_logs_string += f"--- Detection ID: {detection_link.detection_id} ---\n"
                all_logs_string += json.dumps(raw_log_data, indent=2)
                all_logs_string += "\n\n"
                
                log_event_data = raw_log_data.get('collectionElements', [{}])[0].get('references', [{}])[0].get('event', {})
                all_ips.update(extract_ips(log_event_data))
                all_domains.update(extract_domains(log_event_data))
                all_hashes.update(extract_files(log_event_data))
                all_urls.update(extract_urls(log_event_data))

            history = ChatMessage.query.filter_by(incident_id=incident_id).order_by(ChatMessage.timestamp).all()
            chat_history.append({"role": "user", "parts": [{"text": f"Raw Logs for Incident Analysis:\n\n{all_logs_string}\n\n"}]})
            chat_history.append({"role": "model", "parts": [{"text": "I have received the logs. How can I help you analyze them?"}]})
            for msg in history:
                chat_history.append({"role": "user" if msg.sender == 'user' else 'model', "parts": [{"text": msg.message}]})
                
        else:
            if not logs:
                return jsonify({"error": "Logs are required for ad-hoc analysis"}), 400
                
            try:
                logs_data = json.loads(logs)
                for log in logs_data:
                    log_event = log.get('references', [{}])[0].get('event', {})
                    all_ips.update(extract_ips(log_event))
                    all_domains.update(extract_domains(log_event))
                    all_hashes.update(extract_files(log_event))
                    all_urls.update(extract_urls(log_event))

                all_logs_string = json.dumps(logs_data, indent=2)
            except json.JSONDecodeError:
                all_logs_string = logs
                
            chat_history.append({"role": "user", "parts": [{"text": f"Raw Logs for Ad-Hoc Analysis:\n\n{all_logs_string}\n\n"}]})
            chat_history.append({"role": "model", "parts": [{"text": "I have received the ad-hoc logs. How can I help you analyze them?"}]})
        
        threat_intel_prompt = ""
        indicators = {"IP": all_ips, "Domain": all_domains, "File Hash": all_hashes, "URL": all_urls}

        for indicator_type, indicator_set in indicators.items():
            if indicator_set:
                threat_intel_prompt += f"\n\nVirusTotal Reports for {indicator_type}s:\n"
                for indicator in indicator_set:
                    report = get_virustotal_report(indicator)
                    if report:
                        stats = report.get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        harmless = stats.get('harmless', 0)
                        
                        threat_intel_prompt += f"  - {indicator_type}: {indicator}\n"
                        threat_intel_prompt += f"    Status: Malicious ({malicious}), Harmless ({harmless})\n"
                        
                        if malicious > 0:
                            threat_intel_prompt += "    *This indicator is considered malicious.*\n"
                            
                            # Add specific vendor findings to the prompt for more context
                            vendor_findings = report.get('last_analysis_results', {})
                            if vendor_findings:
                                threat_intel_prompt += "    Specific Vendor Findings:\n"
                                for vendor, data in vendor_findings.items():
                                    if data.get('category') == 'malicious' or data.get('category') == 'suspicious':
                                        threat_intel_prompt += f"      - {vendor}: {data.get('result')}\n"
                        else:
                            threat_intel_prompt += "    *This indicator appears to be clean.*\n"
        
        if threat_intel_prompt:
            chat_history.append({"role": "user", "parts": [{"text": threat_intel_prompt}]})


        chat_history.append({"role": "user", "parts": [{"text": prompt}]})

        if not GEMINI_API_KEY:
            return jsonify({"error": "Gemini API key not found."}), 500
        
        system_instruction_payload = {
            "parts": [{ "text": "You are a world-class cybersecurity analyst. Your task is to analyze raw logs and threat intelligence reports provided by the user. Explain your findings in a clear, concise, and professional manner. You must reference specific keys and values from the logs and the threat intelligence reports in your analysis." }]
        }

        payload = {
            "contents": chat_history,
            "system_instruction": system_instruction_payload
        }

        headers = {
            "Content-Type": "application/json"
        }

        response = requests.post(f"{GEMINI_API_URL}?key={GEMINI_API_KEY}", headers=headers, json=payload)
        response.raise_for_status()

        result = response.json()
        generated_text = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'No response from AI.')

        if incident_id:
            user_msg = ChatMessage(incident_id=incident_id, sender='user', message=prompt)
            ai_msg = ChatMessage(incident_id=incident_id, sender='ai', message=generated_text)
            db.session.add(user_msg)
            db.session.add(ai_msg)
            db.session.commit()

        return jsonify({"response": generated_text})

    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"HTTP Error: {e.response.text}"}), e.response.status_code
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route("/api/chat/history/<int:incident_id>", methods=["GET"])
def get_chat_history(incident_id):
    """Retrieves chat history for a specific incident ID."""
    history = ChatMessage.query.filter_by(incident_id=incident_id).order_by(ChatMessage.timestamp).all()
    history_list = [msg.to_dict() for msg in history]
    return jsonify(history_list)

def setup_rule_cache():
    global RULE_METADATA_CACHE
    credentials_file = os.path.join(os.path.dirname(__file__), "nfr4-backstory.json")
    region = os.getenv("CHRONICLE_REGION", "us")
    
    try:
        rules = get_all_rules_by_ids(credentials_file, region, MONITORED_RULE_IDS)
        for rule in rules:
            if 'ruleName' in rule and 'ruleDetails' in rule:
                RULE_METADATA_CACHE[rule['ruleName']] = rule['ruleDetails']
    except Exception as e:
        print(f"Failed to populate rule cache: {e}", file=sys.stderr)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        setup_rule_cache()
    app.run(debug=True)
