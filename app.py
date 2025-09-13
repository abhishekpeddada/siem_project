import datetime
import json
import os
import sys
import requests
from flask import Flask, request, jsonify
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


def get_html_content():
    """Returns the complete HTML content for the web app."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UDM Search & Gemini Chat</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        body {{
            font-family: 'Inter', sans-serif;
            background-color: #121212;
            color: #e0e0e0;
        }}
        .container-main {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            height: 100vh;
        }}
        .panel {{
            padding: 2rem;
            background-color: #1e1e1e;
            border-radius: 0.75rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin: 1rem;
            overflow-y: auto;
        }}
        .input-group label,
        .chat-input-container textarea {{
            color: #b0b0b0;
        }}
        .input-group input, .input-group textarea, .input-group select {{
            background-color: #2c2c2c;
            border: 1px solid #444;
            color: #f5f5f5;
        }}
        .btn-primary {{
            background-color: #6366f1;
            color: white;
            transition: background-color 0.2s;
        }}
        .btn-primary:hover {{
            background-color: #4f46e5;
        }}
        .chat-message.user {{
            background-color: #4f46e5;
            align-self: flex-end;
            text-align: right;
            border-bottom-right-radius: 0;
        }}
        .chat-message.ai {{
            background-color: #444;
            align-self: flex-start;
            border-bottom-left-radius: 0;
        }}
        /* Markdown-specific styling for the AI's response */
        .chat-message.ai h1,
        .chat-message.ai h2,
        .chat-message.ai h3,
        .chat-message.ai h4,
        .chat-message.ai h5,
        .chat-message.ai h6,
        .chat-message.ai strong,
        .chat-message.ai code {{
            color: #ec415e; /* Pinkish-red color */
        }}
        .chat-messages {{
            display: flex;
            flex-direction: column;
        }}
        .chat-container {{
            display: flex;
            flex-direction: column;
            height: 100%;
        }}
        .chat-messages-container {{
            flex-grow: 1;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            padding-right: 0.5rem;
        }}
        .loader {{
          border: 4px solid #f3f3f3;
          border-radius: 50%;
          border-top: 4px solid #3498db;
          width: 24px;
          height: 24px;
          -webkit-animation: spin 2s linear infinite; /* Safari */
          animation: spin 2s linear infinite;
        }}

        /* Safari */
        @-webkit-keyframes spin {{
          0% {{ -webkit-transform: rotate(0deg); }}
          100% {{ -webkit-transform: rotate(360deg); }}
        }}

        @keyframes spin {{
          0% {{ transform: rotate(0deg); }}
          100% {{ transform: rotate(360deg); }}
        }}

        @media (max-width: 768px) {{
            .container-main {{
                grid-template-columns: 1fr;
                height: auto;
            }}
            .panel {{
                margin: 0.5rem;
            }}
        }}
    </style>
</head>
<body class="bg-gray-900 min-h-screen p-4 text-gray-200">
    <div class="container-main max-w-7xl mx-auto">
        <!-- UDM Search Panel -->
        <div class="panel flex flex-col h-full">
            <h2 class="text-3xl font-bold mb-6 text-indigo-400">UDM Search</h2>
            <form id="searchForm" class="space-y-4">
                <div class="input-group">
                    <label for="query" class="block text-sm font-medium mb-1">UDM Query</label>
                    <textarea id="query" name="query" rows="4" class="w-full rounded-md px-3 py-2 text-sm bg-gray-800 border border-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500" placeholder="e.g., principal.ip = '10.12.34.56'" required></textarea>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div class="input-group">
                        <label for="start_time" class="block text-sm font-medium mb-1">Start Time (ISO 8601)</label>
                        <input type="datetime-local" id="start_time" name="start_time" class="w-full rounded-md px-3 py-2 text-sm bg-gray-800 border border-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
                    </div>
                    <div class="input-group">
                        <label for="end_time" class="block text-sm font-medium mb-1">End Time (ISO 8601)</label>
                        <input type="datetime-local" id="end_time" name="end_time" class="w-full rounded-md px-3 py-2 text-sm bg-gray-800 border border-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500" required>
                    </div>
                </div>
                <div class="input-group">
                    <label for="limit" class="block text-sm font-medium mb-1">Limit (1-1000)</label>
                    <input type="number" id="limit" name="limit" value="1000" min="1" max="1000" class="w-full rounded-md px-3 py-2 text-sm bg-gray-800 border border-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                </div>
                <button type="submit" class="w-full rounded-md px-4 py-2 text-sm font-semibold btn-primary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-indigo-500">
                    Search
                </button>
            </form>
            <div id="results" class="mt-8 flex-grow">
                <h3 class="text-xl font-bold mb-4 text-indigo-400">Results</h3>
                <pre id="jsonResults" class="bg-gray-800 p-4 rounded-md text-sm whitespace-pre-wrap overflow-x-auto h-full"></pre>
            </div>
        </div>

        <!-- AI Chat Panel -->
        <div class="panel flex flex-col h-full">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-3xl font-bold text-indigo-400">Gemini Chat</h2>
            </div>
            <div id="chatMessages" class="chat-messages-container flex-grow space-y-4">
                <div class="chat-message ai bg-gray-700 p-4 rounded-xl max-w-sm self-start">
                    Hello! I'm Gemini, your AI assistant. I can help you with your UDM search queries, explain the results, or answer general questions. What can I do for you today?
                </div>
            </div>
            <div class="mt-4 chat-input-container">
                <div class="flex items-center space-x-2">
                    <textarea id="chatInput" rows="1" placeholder="Type your message..." class="flex-grow rounded-md px-4 py-2 text-sm bg-gray-800 border border-gray-700 resize-none focus:outline-none focus:ring-2 focus:ring-indigo-500"></textarea>
                    <button id="sendChatBtn" class="bg-indigo-500 text-white rounded-md p-2 hover:bg-indigo-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-indigo-500 transition duration-150">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path></svg>
                    </button>
                </div>
                <div id="loadingIndicator" class="mt-2 flex items-center justify-center hidden">
                    <div class="loader"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', () => {{
            const searchForm = document.getElementById('searchForm');
            const jsonResults = document.getElementById('jsonResults');
            const chatInput = document.getElementById('chatInput');
            const sendChatBtn = document.getElementById('sendChatBtn');
            const chatMessages = document.getElementById('chatMessages');
            const loadingIndicator = document.getElementById('loadingIndicator');

            const initialAiMessage = `Hello! I'm Gemini, your AI assistant. I can help you with your UDM search queries, explain the results, or answer general questions. What can I do for you today?`;

            // Function to add a message to the chat display
            const addMessage = (text, sender) => {{
                const messageDiv = document.createElement('div');
                messageDiv.classList.add('chat-message', sender, 'p-4', 'rounded-xl', 'max-w-sm', 'text-sm');

                if (sender === 'ai') {{
                    messageDiv.innerHTML = marked.parse(text);
                }} else {{
                    messageDiv.textContent = text;
                }}

                chatMessages.appendChild(messageDiv);
                chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll to the latest message
            }};
            
            // Event listener for the UDM Search form
            searchForm.addEventListener('submit', async (e) => {{
                e.preventDefault();
                jsonResults.textContent = 'Searching...';

                const formData = new FormData(searchForm);
                const query = formData.get('query');
                const start_time = formData.get('start_time');
                const end_time = formData.get('end_time');
                const limit = formData.get('limit');

                try {{
                    const response = await fetch('/search', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{ query, start_time, end_time, limit }}),
                    }});

                    if (!response.ok) {{
                        const errorText = await response.text();
                        throw new Error(`HTTP error! status: ${{response.status}}, message: ${{errorText}}`);
                    }}

                    const data = await response.json();
                    jsonResults.textContent = JSON.stringify(data, null, 2);
                }} catch (error) {{
                    console.error('Error during search:', error);
                    jsonResults.textContent = `Error: ${{error.message}}`;
                }}
            }});

            // Event listener for the Gemini chat input
            sendChatBtn.addEventListener('click', async () => {{
                const prompt = chatInput.value.trim();
                if (!prompt) return;

                addMessage(prompt, 'user');
                chatInput.value = '';
                loadingIndicator.classList.remove('hidden');

                // Get the latest search results from the pre tag
                const logs = jsonResults.textContent.trim();

                try {{
                    const response = await fetch('/chat', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{ prompt, logs }}),
                    }});

                    if (!response.ok) {{
                        throw new Error('Network response was not ok');
                    }}

                    const data = await response.json();
                    addMessage(data.response, 'ai');
                }} catch (error) {{
                    console.error('Error fetching chat response:', error);
                    addMessage('Sorry, I am unable to connect to the AI at the moment. Please try again later.', 'ai');
                }} finally {{
                    loadingIndicator.classList.add('hidden');
                }}
            }});

            // Enable sending message on Enter key press
            chatInput.addEventListener('keydown', (e) => {{
                if (e.key === 'Enter' && !e.shiftKey) {{
                    e.preventDefault();
                    sendChatBtn.click();
                }}
            }});

            // Initial setup for datetime inputs
            const now = new Date();
            const nowISO = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
            document.getElementById('end_time').value = nowISO;
            const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
            const yesterdayISO = new Date(yesterday.getTime() - yesterday.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
            document.getElementById('start_time').value = yesterdayISO;

        }});
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    """Renders the main web application page."""
    return get_html_content()

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
