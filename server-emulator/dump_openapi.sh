#!/bin/bash

./start-server.sh &
SHELL_PID=$!

sleep 1

echo "dump openapi"

curl -X GET "http://localhost:8000/openapi.json" -H  "accept: application/json" | jq > auto_generated_openapi.json

echo "openapi.json created"

echo "stop silk server"
SERVER_PID=$(ps -ef | grep "start-silk-server" | grep -v grep | awk '{print $2}')
kill -9 "$SHELL_PID" "$SERVER_PID"

echo "done"
