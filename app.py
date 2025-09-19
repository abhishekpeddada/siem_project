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

from list_rules import get_all_rules, get_all_rules_by_ids
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

# Hardcoded rule IDs to avoid rate-limiting on a full scan
MONITORED_RULE_IDS = [
    "ru_41baf103-99d9-46cf-8bd7-d2bb3841f8f2",
    "ru_67b85d9f-b743-4ab5-84bc-b4004b2f133c",
    "ru_545584c3-3a45-4b9b-a1bb-dcea39f3bfdb"
]

# --- Database Models ---
class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
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

def correlate_detections_into_incidents(detections):
    """Correlates new detections and groups them into incidents based solely on the user ID."""
    incidents = []
    
    # Correlation logic: group by user ID
    groups = {}
    for det in detections:
        log_data = det.get('collectionElements', [{}])[0].get('references', [{}])[0].get('event', {})
        
        # Reliably get the correlation key (the userid)
        correlation_key = extract_user_id(log_data)
        
        # If no user ID is found, use a unique key to prevent incorrect grouping
        if not correlation_key:
            correlation_key = det.get('id')

        if correlation_key not in groups:
            groups[correlation_key] = []
        groups[correlation_key].append(det)

    for key, group_detections in groups.items():
        existing_incident = None
        # Check for existing incident by the first detection's ID
        first_det_id = group_detections[0].get('id')
        incident_detection = IncidentDetection.query.filter_by(detection_id=first_det_id).first()
        if incident_detection:
            existing_incident = incident_detection.incident
        
        if existing_incident:
            incident = existing_incident
        else:
            # Dynamically set the title based on the correlation key
            if "de_" in key:
                title = f"Incident: Uncategorized Detection {key}"
            else:
                title = f"Incident: Detections for User {key}"
            
            incident = Incident(title=title)
            db.session.add(incident)
            db.session.commit()
            
        # Link detections to the incident
        for det in group_detections:
            if not IncidentDetection.query.filter_by(detection_id=det.get('id')).first():
                incident_detection = IncidentDetection(
                    incident_id=incident.id,
                    detection_id=det.get('id'),
                    raw_data=json.dumps(det)
                )
                db.session.add(incident_detection)
        db.session.commit()
        incidents.append(incident)
        
    return incidents

@app.route("/")
def dashboard():
    """Renders the main dashboard, listing all incidents."""
    try:
        # Fetch detections for monitored rules and create/update incidents
        end_time_obj = datetime.datetime.now(datetime.timezone.utc)
        start_time_obj = end_time_obj - datetime.timedelta(hours=24)
        start_time_iso = start_time_obj.isoformat(timespec='seconds').replace('+00:00', 'Z')
        end_time_iso = end_time_obj.isoformat(timespec='seconds').replace('+00:00', 'Z')
        
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

        # Now, fetch all incidents to display on the dashboard
        incidents = Incident.query.order_by(Incident.created_at.desc()).all()
        return render_template("dashboard.html", incidents=incidents)
    except Exception as e:
        return f"An error occurred: {e}", 500

@app.route("/incidents/<int:incident_id>")
def incident_details(incident_id):
    """Renders the details page for a specific incident."""
    incident = Incident.query.get_or_404(incident_id)
    # Get the raw detection data for this incident
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

# In app.py, replace the existing chat() function with this one

@app.route("/api/chat", methods=["POST"])
def chat():
    """Handles the Gemini chat request for log analysis."""
    try:
        data = request.json
        prompt = data.get("prompt")
        incident_id = data.get("incident_id")
        logs = data.get("logs") # This is a new field to handle ad-hoc logs
        
        if not prompt:
            return jsonify({"error": "Prompt is required"}), 400

        chat_history = []
        
        if incident_id:
            # Logic for Incident-based chat (existing functionality)
            incident = Incident.query.get_or_404(incident_id)
            all_logs_string = ""
            for detection_link in incident.detections:
                all_logs_string += f"--- Detection ID: {detection_link.detection_id} ---\n"
                all_logs_string += json.dumps(json.loads(detection_link.raw_data), indent=2)
                all_logs_string += "\n\n"

            history = ChatMessage.query.filter_by(incident_id=incident_id).order_by(ChatMessage.timestamp).all()
            chat_history.append({"role": "user", "parts": [{"text": f"Raw Logs for Incident Analysis:\n\n{all_logs_string}\n\n"}]})
            chat_history.append({"role": "model", "parts": [{"text": "I have received the logs. How can I help you analyze them?"}]})
            for msg in history:
                chat_history.append({"role": "user" if msg.sender == 'user' else 'model', "parts": [{"text": msg.message}]})
        else:
            # Logic for ad-hoc UDM search (new functionality)
            if not logs:
                return jsonify({"error": "Logs are required for ad-hoc analysis"}), 400
            chat_history.append({"role": "user", "parts": [{"text": f"Raw Logs for Ad-Hoc Analysis:\n\n{logs}\n\n"}]})
            chat_history.append({"role": "model", "parts": [{"text": "I have received the ad-hoc logs. How can I help you analyze them?"}]})

        chat_history.append({"role": "user", "parts": [{"text": prompt}]})

        if not GEMINI_API_KEY:
            return jsonify({"error": "Gemini API key not found."}), 500
        
        system_instruction_payload = {
            "parts": [{ "text": "You are a world-class cybersecurity analyst. Your task is to analyze raw logs provided by the user and respond to their questions based on those logs. Explain your findings in a clear, concise, and professional manner. You must reference specific keys and values from the logs in your analysis." }]
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

        # Only save messages to the database if an incident ID is present
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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
