#!/usr/bin/env python3
"""
Simple startup script for the Wazuh LLM Assistant
"""
import subprocess
import sys
import time
import requests


def check_api_health():
    """Check if the API is running"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def start_api_server():
    """Start the FastAPI server"""
    print("Starting FastAPI server...")
    subprocess.Popen([
        sys.executable, "main.py"
    ])


def start_streamlit():
    """Start the Streamlit UI"""
    print("Starting Streamlit UI...")
    subprocess.run([
        sys.executable, "-m", "streamlit", "run", "streamlit_ui.py",
        "--server.headless", "true",
        "--server.port", "8501",
        "--browser.gatherUsageStats", "false"
    ])


def main():
    """Main startup function"""
    print("Wazuh LLM Security Assistant")
    print("=" * 50)
    
    # Check if API is already running
    if not check_api_health():
        print("API server not detected, starting...")
        start_api_server()
        
        # Wait for API to start
        for i in range(30):  # Wait up to 30 seconds
            if check_api_health():
                print("API server started successfully!")
                break
            time.sleep(1)
            print(f"Waiting for API server... ({i+1}/30)")
        else:
            print("Failed to start API server!")
            print("Please check your configuration and try running 'python main.py' manually.")
            sys.exit(1)
    else:
        print("API server already running!")
    
    # Start Streamlit UI
    print("\nStarting Streamlit UI...")
    print("UI will be available at: http://localhost:8501")
    print("Press Ctrl+C to stop both services")
    
    try:
        start_streamlit()
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
