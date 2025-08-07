#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to start the server
start_server() {
  # Navigate to the script directory
  cd "$SCRIPT_DIR" || exit 1

  # Check if the virtual environment 'venv' exists, if not, create it
  if [ ! -d "venv" ]; then
    python3 -m venv venv
  fi

  # Activate the virtual environment
  source venv/bin/activate

  # Install the required packages from 'requirements.txt'
  pip install -r requirements.txt

  # Set the environment variable for PORT
  export PORT=14145

  # Run the fast_mcp.py script with or without debug logs
  if [ "$1" == "-d" ]; then
    echo "Starting Zoho server with debug logs..."
    # Run in foreground with logs visible
    python fast_mcp.py
    # This point will only be reached when the server stops
    echo "Server stopped."
  else
    echo "Starting Zoho server in background..."
    nohup python fast_mcp.py > /dev/null 2>&1 &
    echo "Server started with PID: $!"
    
    # Save the PID to a file for easier management
    echo $! > "$SCRIPT_DIR/.zoho_server_pid"
  fi
}

# Function to stop the server
stop_server() {
  echo "Stopping Zoho server..."
  if [ -f "$SCRIPT_DIR/.zoho_server_pid" ]; then
    PID=$(cat "$SCRIPT_DIR/.zoho_server_pid")
    if ps -p "$PID" > /dev/null; then
      kill "$PID"
      echo "Server with PID $PID stopped."
      rm "$SCRIPT_DIR/.zoho_server_pid"
    else
      echo "Server process not found. Cleaning up PID file."
      rm "$SCRIPT_DIR/.zoho_server_pid"
      pkill -f "python.*fast_mcp.py" || echo "No Zoho server processes found."
    fi
  else
    pkill -f "python.*fast_mcp.py" || echo "No Zoho server processes found."
  fi
}

# Function to check server status
check_status() {
  if [ -f "$SCRIPT_DIR/.zoho_server_pid" ]; then
    PID=$(cat "$SCRIPT_DIR/.zoho_server_pid")
    if ps -p "$PID" > /dev/null; then
      echo "Zoho server is running with PID: $PID"
    else
      echo "Zoho server is not running (stale PID file found)"
      rm "$SCRIPT_DIR/.zoho_server_pid"
    fi
  else
    if pgrep -f "python.*fast_mcp.py" > /dev/null; then
      echo "Zoho server is running (PID file missing)"
    else
      echo "Zoho server is not running"
    fi
  fi
}

# Main script execution
case "$1" in
  "start")
    # Kill any existing processes before starting
    pkill -f "python.*fast_mcp.py" || true
    start_server "$2"
    ;;
  "stop")
    stop_server
    ;;
  "status")
    check_status
    ;;
  *)
    echo "Usage: Zoho {start|stop|status} [-d]"
    echo "  start     - Start the Zoho server in background"
    echo "  start -d  - Start the Zoho server in background with debug logs"
    echo "  stop      - Stop the Zoho server"
    echo "  status    - Check if the Zoho server is running"
    exit 1
    ;;
esac
