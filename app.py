import os
import json
import sys
import requests
import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for
import google.generativeai as genai
from dotenv import load_dotenv
from typing import Any, Mapping, Optional, Sequence, Tuple

from list_rules import get_all_rules
from list_detections import get_detections_for_rule
from common import chronicle_auth
from common import regions

load_dotenv()

app = Flask(__name__)

# Configure Gemini AI
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Define variables for Chronicle API access
CHRONICLE_CREDENTIALS_FILE = os.path.join(os.path.dirname(__file__), "nfr4-backstory.json")
CHRONICLE_REGION = os.getenv("CHRONICLE_REGION", "us")
UDM_API_BASE_URL = "https://backstory.googleapis.com"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


def format_to_chronicle_time(dt_str: str) -> Optional[str]:
    """
    Converts a datetime-local string (YYYY-MM-DDTHH:MM) to a
    UTC ISO 8601 string (YYYY-MM-DDThh:mm:ssZ) for Chronicle API.
    """
    if not dt_str:
        return None
    try:
        dt_obj = datetime.datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")
        utc_dt = dt_obj.replace(tzinfo=datetime.timezone.utc)
        return utc_dt.isoformat(timespec='seconds').replace('+00:00', 'Z')
    except ValueError:
        return None


def real_udm_search(query: str, start_time: datetime.datetime, end_time: datetime.datetime, limit: int) -> Mapping[str, Any]:
    """Performs a UDM search against the real API.
    """
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


# Routes
@app.route("/")
def dashboard():
    """
    Renders the main dashboard page, listing all rules.
    """
    try:
        rules = get_all_rules(CHRONICLE_CREDENTIALS_FILE, CHRONICLE_REGION)
        return render_template("dashboard.html", rules=rules)
    except Exception as e:
        return f"An error occurred: {e}", 500


@app.route("/detections/<version_id>")
def detection_details(version_id):
    """
    Renders the detections page for a specific rule version.
    """
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
        
        if not start_time_iso or not end_time_iso:
            return "Invalid date or time range.", 400

        detections, _ = get_detections_for_rule(
            version_id=version_id,
            start_time=start_time_iso,
            end_time=end_time_iso,
            list_basis="DETECTION_TIME",
            alert_state="ALERTING",
            credentials_file=CHRONICLE_CREDENTIALS_FILE,
            region=CHRONICLE_REGION
        )

        return render_template(
            "detection_details.html",
            detections=detections,
            version_id=version_id,
            start_time=start_time_str,
            end_time=end_time_str
        )
    except Exception as e:
        return f"An error occurred: {e}", 500

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
        logs = data.get("logs")
        
        if not prompt or not logs:
            return jsonify({"error": "Prompt and logs are required"}), 400

        final_prompt = (
            f"You are a world-class cybersecurity analyst. Your task is to analyze the following raw logs "
            f"and respond to the user's question based on them. Explain your findings in a clear, concise, "
            f"and professional manner. You must reference specific keys and values from the logs in your analysis.\n\n"
            f"Raw Logs:\n{logs}\n\n"
            f"User's Question: {prompt}"
        )
        
        if not GEMINI_API_KEY:
            return jsonify({"error": "Gemini API key not found. Please set the GEMINI_API_KEY environment variable."}), 500

        payload = {
            "contents": [{"role": "user", "parts": [{"text": final_prompt}]}]
        }

        headers = {
            "Content-Type": "application/json"
        }

        response = requests.post(f"{GEMINI_API_URL}?key={GEMINI_API_KEY}", headers=headers, json=payload)
        response.raise_for_status()

        result = response.json()
        generated_text = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'No response from AI.')

        return jsonify({"response": generated_text})

    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"HTTP Error: {e.response.text}"}), e.response.status_code
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
