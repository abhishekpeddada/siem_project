UDM Search & Gemini Chat

This is a web application that integrates Google Chronicle's Unified Data Model (UDM) search functionality with a Gemini-powered AI chat interface. The application allows users to perform UDM queries and receive human-readable explanations and analysis of the results directly from an AI assistant.

The application is built with a Python Flask backend and a modern, responsive HTML/JavaScript frontend using Tailwind CSS for styling. Chat history is made persistent by storing it in a SQLite database.


Features

    UDM Search: Submit UDM queries with specified time ranges and limits.

    AI-Powered Analysis: A Gemini AI assistant analyzes the search results and provides insights.

Setup and Installation
Prerequisites

    Python 3.8 or higher

    A Google Cloud Service Account with access to Chronicle API.

    A Gemini API key.

Getting Started

    Clone the repository:

    git clone [https://github.com/abhishekpeddada/siem_project.git](https://github.com/abhishekpeddada/siem_project.git)
    cd siem_project

    Set up a Python virtual environment:

    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

    Install dependencies:

    pip install Flask Flask-SQLAlchemy python-dotenv requests google-auth google-auth-oauthlib

    Configure environment variables:
    Create a .env file in the root directory of the project and add your credentials.

    GEMINI_API_KEY="your-gemini-api-key"
    CHRONICLE_CREDENTIALS_PATH="/path/to/your/service-account.json"

    Run the application:

    python app.py

The application will be running at http://127.0.0.1:5000.

Credits

The core logic for performing the UDM search and handling authentication with the Chronicle API is based on the official Chronicle API Python Samples. Specifically, the real_udm_search function and related authentication boilerplate were adapted from search/udm_search.py.
