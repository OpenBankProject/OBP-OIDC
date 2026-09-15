#!/bin/bash

# Copyright (c) 2025 TESOBE
#
# This file is part of OBP-OIDC.
#
# OBP-OIDC is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OBP-OIDC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with OBP-OIDC. If not, see <http://www.gnu.org/licenses/>.

# OBP-OIDC Server Runner Script
# This script loads environment variables from .env and starts the OIDC server
#
# TRACE Logging:
# To enable detailed TRACE level logs for debugging:
#   OIDC_ENABLE_TRACE_LOGGING=true ./run-server.sh

echo "Starting OBP-OIDC Server..."
echo "================================="

# Load environment variables from .env file
if [ -f ".env" ]; then
    echo "Loading configuration from .env file..."
    # Export variables from .env file, ignoring comments and empty lines
    set -a
    source .env
    set +a
    echo "Configuration loaded successfully"
else
    echo "Error: .env file not found!"
    echo "Please create a .env file based on .env.example:"
    echo "  cp .env.example .env"
    echo "Then edit .env with your configuration values"
    exit 1
fi

echo ""
echo "Configuration:"
echo "  Server: $OIDC_HOST:$OIDC_PORT"
echo "  Issuer: obp-oidc (hardcoded)"
echo "  Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "  Read User: $OIDC_USER_USERNAME"
echo "  Admin User: $OIDC_ADMIN_USERNAME"
echo "  Client Bootstrap: ${OIDC_SKIP_CLIENT_BOOTSTRAP:-false}"
echo ""
echo "Note: OIDC clients will be auto-generated on first startup"
echo "      Copy the client configurations from server output to your apps"
echo ""

# Logging Configuration
if [ "$OIDC_ENABLE_TRACE_LOGGING" = "true" ]; then
    echo "TRACE logging: ENABLED (detailed debugging)"
else
    echo "TRACE logging: DISABLED (use OIDC_ENABLE_TRACE_LOGGING=true to enable)"
fi

# JAR file path
JAR_FILE="target/obp-oidc-1.0.0-SNAPSHOT.jar"

# Check if JAR exists
if [ ! -f "$JAR_FILE" ]; then
    echo "Error: JAR file not found at $JAR_FILE"
    echo "Please run './build_and_run_server.sh' to build and run, or build manually with 'mvn clean package -DskipTests'"
    exit 1
fi

echo "Using existing JAR: $JAR_FILE"
echo ""
echo "Starting OIDC server..."
echo "   Health Check: http://$OIDC_HOST:$OIDC_PORT/health"
echo "   Discovery: http://$OIDC_HOST:$OIDC_PORT/.well-known/openid-configuration"
echo "   JWKS: http://$OIDC_HOST:$OIDC_PORT/jwks"
echo ""
echo "Note: OIDC client configurations will be printed on startup"
echo "   Copy the configurations from the server output to your service Props/env files"
echo ""
echo "Press Ctrl+C to stop the server"
echo "================================="

# Function to handle cleanup on script exit
cleanup() {
    echo ""
    echo "Shutting down server..."
    if [ ! -z "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    echo "Server stopped"
    exit 0
}

# Trap signals to ensure proper cleanup
trap cleanup SIGINT SIGTERM

# Run the server with optional TRACE logging
if [ "$OIDC_ENABLE_TRACE_LOGGING" = "true" ]; then
    echo "TRACE logging enabled for detailed debugging"
    java $JAVA_OPTS -Dlogback.logger.com.tesobe.oidc.level=TRACE -jar "$JAR_FILE" &
else
    java $JAVA_OPTS -jar "$JAR_FILE" &
fi

# Store the server process ID
SERVER_PID=$!

# Wait for the server process to complete
wait "$SERVER_PID"

# If we get here, the server exited on its own
echo "Server process finished"
