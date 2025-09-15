import datetime
import json
import os
import sys
import requests
from flask import Flask, request, jsonify, render_template  # Import render_template
from flask_sqlalchemy import SQLAlchemy
from typing import Any, Mapping, Optional
from dotenv import load_dotenv

from google.auth.transport import requests as auth_requests
from google.oauth2 import service_account

from common import chronicle_auth
from common import regions

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///udm_searches.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent"
UDM_API_BASE_URL = "https://backstory.googleapis.com"

CHRONICLE_CREDENTIALS_PATH = os.environ.get("CHRONICLE_CREDENTIALS_PATH")

# Database Model for Search History
class Search(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    query = db.Column(db.String(500), nullable=False)
    start_time = db.Column(db.String(50), nullable=False)
    end_time = db.Column(db.String(50), nullable=False)
    limit = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f'<Search {self.query}>'

def real_udm_search(query: str, start_time: datetime.datetime, end_time: datetime.datetime, limit: int) -> Mapping[str, Any]:
    """Performs a UDM search against the real API.
    
    NOTE: This function requires a valid Google Service Account JSON key.
    
    Args:
      query: UDM search query.
      start_time: Inclusive beginning of the time range.
      end_time: Exclusive end of the time range.
      limit: Maximum number of matched events to return.
      
    Returns:
      A dictionary containing the search results.
      
    Raises:
      requests.exceptions.HTTPError: If the API request fails.
    """
    
    if not CHRONICLE_CREDENTIALS_PATH or not os.path.exists(CHRONICLE_CREDENTIALS_PATH):
        raise FileNotFoundError(f"Chronicle credentials file not found at path: {CHRONICLE_CREDENTIALS_PATH}. Please set the CHRONICLE_CREDENTIALS_PATH environment variable.")

    try:
        http_session = chronicle_auth.initialize_http_session(CHRONICLE_CREDENTIALS_PATH)
    except Exception as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        raise Exception(f"Authentication failed: {e}")

    region = "us"
    api_url = regions.url(UDM_API_BASE_URL, region)
    url = f"{api_url}/v1/events:udmSearch"
    s = start_time.isoformat() + 'Z'
    e = end_time.isoformat() + 'Z'
    params = {
        "query": query,
        "time_range.start_time": s,
        "time_range.end_time": e,
        "limit": limit
    }
    
    response = http_session.request("GET", url, params=params)
    response.raise_for_status()
    return response.json()

@app.route("/")
def index():
    """Renders the main web application page."""
    return render_template('index.html')

@app.route("/search", methods=["POST"])
def search():
    """Handles the UDM search request."""
    try:
        data = request.json
        query = data.get("query")
        start_time_str = data.get("start_time")
        end_time_str = data.get("end_time")
        limit = int(data.get("limit"))

        if not all([query, start_time_str, end_time_str]):
            return jsonify({"error": "Missing required fields"}), 400

        start_time = datetime.datetime.fromisoformat(start_time_str)
        end_time = datetime.datetime.fromisoformat(end_time_str)

        if start_time >= end_time:
            return jsonify({"error": "Start time must be before end time"}), 400
        if limit < 1 or limit > 1000:
            return jsonify({"error": "Limit must be between 1 and 1000"}), 400

        new_search = Search(query=query, start_time=start_time_str, end_time=end_time_str, limit=limit)
        db.session.add(new_search)
        db.session.commit()

        results = real_udm_search(query, start_time, end_time, limit)

        return jsonify(results)

    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route("/chat", methods=["POST"])
def chat():
    """Handles the Gemini chat request."""
    try:
        data = request.json
        prompt = data.get("prompt")
        logs = data.get("logs")
        
        if not prompt:
            return jsonify({"error": "Prompt is required"}), 400

        chat_history = []
        initial_log_prompt = f"Raw Logs for Analysis:\n\n{logs}\n\n"
        chat_history.append({"role": "user", "parts": [{"text": initial_log_prompt}]})
        chat_history.append({"role": "model", "parts": [{"text": "I have received the logs. How can I help you analyze them?"}]})
        chat_history.append({"role": "user", "parts": [{"text": prompt}]})

        # Define the AI persona
        system_instruction = {
            "parts": [{ "text": "You are a world-class cybersecurity analyst. Your task is to analyze raw logs provided by the user and respond to their questions based on those logs. Explain your findings in a clear, concise, and professional manner. You must reference specific keys and values from the logs in your analysis." }]
        }
        
        if not GEMINI_API_KEY:
            return jsonify({"error": "Gemini API key not found. Please set the GEMINI_API_KEY environment variable."}), 500

        payload = {
            "contents": chat_history,
            "systemInstruction": system_instruction
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
    with app.app_context():
        db.create_all()
    app.run(debug=True)
