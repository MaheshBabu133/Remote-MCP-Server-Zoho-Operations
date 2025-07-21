#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Default port number
DEFAULT_PORT=14145

# Function to start the server
start_server() {
  local debug_mode=false
  local port=$DEFAULT_PORT
  
  # Parse arguments
  if [ "$1" == "-d" ]; then
    debug_mode=true
    # Check if a port number is provided after -d
    if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
      port=$2
    fi
  elif [[ -n "$1" && "$1" =~ ^[0-9]+$ ]]; then
    port=$1
  fi
  
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
  export PORT=$port

  # Kill any existing processes running on this port
  kill_process_on_port $port

  # Run the fast_mcp.py script with or without debug logs
  if [ "$debug_mode" = true ]; then
    echo "Starting Zoho server on port $port with debug logs..."
    # Run in foreground with logs visible
    python fast_mcp.py
    # This point will only be reached when the server stops
    echo "Server stopped."
  else
    echo "Starting Zoho server on port $port in background..."
    nohup python fast_mcp.py > /dev/null 2>&1 &
    echo "Server started with PID: $! on port $port"
    
    # Save the PID to a file for easier management (include port in filename)
    echo $! > "$SCRIPT_DIR/.zoho_server_pid_$port"
  fi
}

# Function to kill process running on a specific port
kill_process_on_port() {
  local port=$1
  local pid
  
  # Find process using the port
  pid=$(lsof -t -i:"$port" 2>/dev/null)
  
  if [ -n "$pid" ]; then
    echo "Killing process $pid running on port $port"
    kill $pid 2>/dev/null || kill -9 $pid 2>/dev/null
    return 0
  fi
  return 1
}

# Function to stop the server
stop_server() {
  local port=$DEFAULT_PORT
  
  # Check if a port number is provided
  if [[ -n "$1" && "$1" =~ ^[0-9]+$ ]]; then
    port=$1
  fi
  
  echo "Stopping Zoho server on port $port..."
  
  # Try to stop using PID file first
  if [ -f "$SCRIPT_DIR/.zoho_server_pid_$port" ]; then
    PID=$(cat "$SCRIPT_DIR/.zoho_server_pid_$port")
    if ps -p "$PID" > /dev/null; then
      kill "$PID"
      echo "Server with PID $PID on port $port stopped."
      rm "$SCRIPT_DIR/.zoho_server_pid_$port"
    else
      echo "Server process not found. Cleaning up PID file."
      rm "$SCRIPT_DIR/.zoho_server_pid_$port"
      # Try to kill by port
      kill_process_on_port $port || echo "No process found on port $port."
    fi
  else
    # Try to kill by port
    kill_process_on_port $port || echo "No process found on port $port."
    
    # For backward compatibility, also check the old PID file
    if [ "$port" = "$DEFAULT_PORT" ] && [ -f "$SCRIPT_DIR/.zoho_server_pid" ]; then
      PID=$(cat "$SCRIPT_DIR/.zoho_server_pid")
      if ps -p "$PID" > /dev/null; then
        kill "$PID"
        echo "Server with PID $PID stopped (using legacy PID file)."
      fi
      rm "$SCRIPT_DIR/.zoho_server_pid"
    fi
  fi
}

# Function to check server status
check_status() {
  local port=$DEFAULT_PORT
  
  # Check if a port number is provided
  if [[ -n "$1" && "$1" =~ ^[0-9]+$ ]]; then
    port=$1
  fi
  
  # Check if process is running on the specified port
  local pid
  pid=$(lsof -t -i:"$port" 2>/dev/null)
  
  if [ -n "$pid" ]; then
    echo "Zoho server is running on port $port with PID: $pid"
    return
  fi
  
  # Check using PID file
  if [ -f "$SCRIPT_DIR/.zoho_server_pid_$port" ]; then
    PID=$(cat "$SCRIPT_DIR/.zoho_server_pid_$port")
    if ps -p "$PID" > /dev/null; then
      echo "Zoho server is running on port $port with PID: $PID"
    else
      echo "Zoho server is not running on port $port (stale PID file found)"
      rm "$SCRIPT_DIR/.zoho_server_pid_$port"
    fi
  else
    # For backward compatibility, also check the old PID file if using default port
    if [ "$port" = "$DEFAULT_PORT" ] && [ -f "$SCRIPT_DIR/.zoho_server_pid" ]; then
      PID=$(cat "$SCRIPT_DIR/.zoho_server_pid")
      if ps -p "$PID" > /dev/null; then
        echo "Zoho server is running on default port with PID: $PID (using legacy PID file)"
      else
        echo "Zoho server is not running on default port (stale legacy PID file found)"
        rm "$SCRIPT_DIR/.zoho_server_pid"
      fi
    else
      echo "Zoho server is not running on port $port"
    fi
  fi
}

# Main script execution
case "$1" in
  "start")
    if [ "$2" == "-d" ]; then
      # Debug mode
      if [[ -n "$3" && "$3" =~ ^[0-9]+$ ]]; then
        # With custom port
        start_server "-d" "$3"
      else
        # With default port
        start_server "-d"
      fi
    elif [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
      # Custom port without debug
      start_server "$2"
    else
      # Default port without debug
      start_server
    fi
    ;;
  "stop")
    if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
      # Stop server on custom port
      stop_server "$2"
    else
      # Stop server on default port
      stop_server
    fi
    ;;
  "status")
    if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
      # Check status on custom port
      check_status "$2"
    else
      # Check status on default port
      check_status
    fi
    ;;
  *)
    echo "Usage: ./manage.sh {start|stop|status} [options]"
    echo "Options:"
    echo "  start           - Start the Zoho server on default port (14145) in background"
    echo "  start -d        - Start the Zoho server on default port with debug logs"
    echo "  start <port>    - Start the Zoho server on custom port in background"
    echo "  start -d <port> - Start the Zoho server on custom port with debug logs"
    echo "  stop            - Stop the Zoho server on default port"
    echo "  stop <port>     - Stop the Zoho server on custom port"
    echo "  status          - Check if the Zoho server is running on default port"
    echo "  status <port>   - Check if the Zoho server is running on custom port"
    exit 1
    ;;
esac
