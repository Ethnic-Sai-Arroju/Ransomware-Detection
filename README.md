# Ransomware Detection System

A Flask-based web application for detecting ransomware in executable files.

## Features

- Upload and scan EXE, DLL, and ZIP files
- Machine learning-based detection
- Modern responsive UI
- Secure file handling

## Deployment on Render

1. Create a new Render account if you don't have one
2. Create a new Web Service
3. Connect your GitHub/GitLab repository
4. Render will automatically detect the `render.yaml` and deploy the application

## Local Development

1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the environment:
   - Windows: `venv\Scripts\activate`
   - Unix/MacOS: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Run the app: `python app/main.py`