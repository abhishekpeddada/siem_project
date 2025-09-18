# app.py

import os
import json
from flask import Flask, render_template, request, jsonify
import google.generativeai as genai
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

# Load environment variables from .env file
load_dotenv()

# Import the refactored scripts
from list_rules import get_all_rules
from list_detections import get_detections_for_rule

app = Flask(__name__)

# Configure Gemini AI with the new model name
# Note: You need to ensure your API key has access to this model.
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Define variables for Chronicle API access
CHRONICLE_CREDENTIALS_FILE = os.getenv("CHRONICLE_CREDENTIALS_FILE")
CHRONICLE_REGION = os.getenv("CHRONICLE_REGION", "us")


def format_datetime_to_iso(dt_str):
    """
    Converts a datetime-local string (YYYY-MM-DDTHH:MM) to
    a UTC ISO 8601 string (YYYY-MM-DDThh:mm:ssZ).
    """
    if not dt_str:
        return None
    try:
        # datetime-local format: 'YYYY-MM-DDTHH:MM'
        dt_obj = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")
        # Set timezone to UTC, as the form input is treated as local
        dt_obj_utc = dt_obj.replace(tzinfo=timezone.utc)
        # Format to ISO 8601 with 'Z' suffix
        return dt_obj_utc.isoformat(timespec='seconds').replace('+00:00', 'Z')
    except ValueError:
        # Handle cases where the format is incorrect
        return None

# Routes
@app.route("/")
def dashboard():
    """
    Renders the main dashboard page.
    Fetches all rules and displays them.
    """
    try:
        rules = get_all_rules(CHRONICLE_CREDENTIALS_FILE, CHRONICLE_REGION)
        return render_template("dashboard.html", rules=rules)
    except Exception as e:
        return f"An error occurred: {e}", 500

@app.route("/detections/<version_id>")
def detection_details(version_id):
    """
    Renders the detections page for a specific rule.
    Fetches detections based on the rule's version ID and a specified timeframe.
    """
    try:
        # Get start and end times from form
        start_time_str = request.args.get("start_time")
        end_time_str = request.args.get("end_time")

        # Set default times if none are provided
        if not start_time_str or not end_time_str:
            end_time_obj = datetime.now(timezone.utc)
            start_time_obj = end_time_obj - timedelta(hours=24)
            start_time_str = start_time_obj.strftime("%Y-%m-%dT%H:%M")
            end_time_str = end_time_obj.strftime("%Y-%m-%dT%H:%M")

        # Convert the string from the form to the format required by the API
        chronicle_start_time = format_datetime_to_iso(start_time_str)
        chronicle_end_time = format_datetime_to_iso(end_time_str)

        # Handle the case where conversion fails
        if not chronicle_start_time or not chronicle_end_time:
            return "Invalid date format provided.", 400

        # Pass the ISO 8601 strings to the `get_detections_for_rule` function
        detections, _ = get_detections_for_rule(
            version_id=version_id,
            start_time=chronicle_start_time,
            end_time=chronicle_end_time,
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
        
@app.route("/api/chat", methods=["POST"])
def chat():
    """
    API endpoint for the Gemini AI chat.
    Takes raw log data and a user message and returns an AI response.
    """
    data = request.json
    logs = data.get("logs", "")
    user_message = data.get("message", "")

    if not logs or not user_message:
        return jsonify({"error": "Logs and message are required."}), 400

    try:
        # Correct the model name here
        model = genai.GenerativeModel("gemini-1.5-flash-latest")
        prompt = f"Analyze the following security logs and provide an explanation. Also, answer this question: {user_message}\n\nLogs:\n{logs}"
        response = model.generate_content(prompt)
        return jsonify({"response": response.text})
    except Exception as e:
        return jsonify({"error": f"An error occurred with the AI: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=True)
