#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SERVER_DIR/venv"
PID_FILE="$SERVER_DIR/mcp_router.pid"
LOG_FILE="$SERVER_DIR/mcp_router.log"
REQUIREMENTS_FILE="$SERVER_DIR/requirements.txt"
PYTHON_CMD="python3"
SERVER_SCRIPT="$SERVER_DIR/main.py"
DEFAULT_PORT=30202

# Check if Python 3 is installed
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

# Function to check if server is running
is_running() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            return 0
        else
            rm -f "$PID_FILE"
            return 1
        fi
    fi
    return 1
}

# Function to install dependencies
install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$VENV_DIR" ]; then
        echo "Creating virtual environment..."
        $PYTHON_CMD -m venv "$VENV_DIR"
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to create virtual environment${NC}"
            exit 1
        fi
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements if file exists
    if [ -f "$REQUIREMENTS_FILE" ]; then
        echo "Installing from requirements.txt..."
        pip install -r "$REQUIREMENTS_FILE"
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to install requirements${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}No requirements.txt found, installing basic dependencies...${NC}"
        pip install fastmcp python-dotenv openai
    fi
    
    echo -e "${GREEN}Dependencies installed successfully${NC}"
}

# Function to start the server
start_server() {
    local port=$DEFAULT_PORT
    local run_in_background=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                port=$2
                shift 2
                ;;
            --background)
                run_in_background=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    
    if is_running; then
        echo -e "${YELLOW}MCP Router server is already running (PID: $(cat "$PID_FILE"))${NC}"
        return 0
    fi
    
    echo -e "${YELLOW}Starting MCP Router server on port $port...${NC}"
    
    # Install dependencies if needed
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${YELLOW}Virtual environment not found. Installing dependencies...${NC}"
        install_dependencies
    fi
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    
    # Change to server directory
    cd "$SERVER_DIR"
    
    if [ "$run_in_background" = true ]; then
        echo -e "${GREEN}Starting server in background mode${NC}"
        # Start the server in background
        nohup $PYTHON_CMD "$SERVER_SCRIPT" --host 0.0.0.0 --port "$port" > "$LOG_FILE" 2>&1 &
        local server_pid=$!
        
        # Save PID
        echo $server_pid > "$PID_FILE"
        
        # Wait a moment to check if server started successfully
        sleep 2
        
        if is_running; then
            echo -e "${GREEN}MCP Router server started successfully! PID: $server_pid${NC}"
            echo -e "${GREEN}Server is running at http://localhost:$port${NC}"
            echo -e "${YELLOW}Logs are being written to: $LOG_FILE${NC}"
            return 0
        else
            echo -e "${RED}Failed to start MCP Router server${NC}"
            echo -e "${RED}Check log file: $LOG_FILE${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}Server will run in the foreground. Press Ctrl+C to stop.${NC}"
        $PYTHON_CMD "$SERVER_SCRIPT" --host 0.0.0.0 --port "$port"
    fi
}

# Function to stop the server
stop_server() {
    if ! is_running; then
        echo -e "${YELLOW}MCP Router server is not running${NC}"
        return 0
    fi
    
    local pid
    pid=$(cat "$PID_FILE")
    echo -e "${YELLOW}Stopping MCP Router server (PID: $pid)...${NC}"
    
    kill -TERM "$pid"
    rm -f "$PID_FILE"
    echo -e "${GREEN}MCP Router server stopped${NC}"
}

# Function to show server status
status() {
    if is_running; then
        echo -e "${GREEN}MCP Router server is running (PID: $(cat "$PID_FILE"))${NC}"
    else
        echo -e "${RED}MCP Router server is not running${NC}"
    fi
}

# Function to show logs
tail_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo -e "${RED}Log file not found: $LOG_FILE${NC}"
    fi
}

# Main script
case "$1" in
    start)
        shift  # Remove 'start' from arguments
        start_server "$@"
        ;;
    stop)
        stop_server
        ;;
    restart)
        stop_server
        sleep 1
        shift  # Remove 'restart' from arguments
        start_server "$@"
        ;;
    status)
        status
        ;;
    logs)
        tail_logs
        ;;
    install)
        install_dependencies
        ;;
    *)
        echo "Usage: $0 {start [--port PORT] [--background]|stop|restart [--port PORT] [--background]|status|logs|install}"
        echo ""
        echo "Commands:"
        echo "  start [--port PORT] [--background]   - Start the MCP Router server (default port: $DEFAULT_PORT)"
        echo "  stop                                 - Stop the MCP Router server"
        echo "  restart [--port PORT] [--background] - Restart the MCP Router server"
        echo "  status                               - Show server status"
        echo "  logs                                 - Show server logs (tail -f)"
        echo "  install                              - Install/update dependencies"
        echo ""
        echo "Additional flags for start/restart:"
        echo "  --port PORT      - Specify port number (default: $DEFAULT_PORT)"
        echo "  --background     - Run server in background mode"
        exit 1
        ;;
esac