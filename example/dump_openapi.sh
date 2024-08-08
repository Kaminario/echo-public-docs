#!/bin/bash

# activate env if not already activated

if [ -z "$VIRTUAL_ENV" ]; then
    echo "activate virtual environment"
    source .venv/bin/activate
fi

# start server and keep is PID for later stop
echo "start silk server"

start-silk-server &
PID=$!

sleep 1
echo "dump openapi"

curl -X GET "http://localhost:8000/openapi.json" -H  "accept: application/json" | jq > openapi.json

echo "openapi.json created"

# stop server
echo "stop silk server"

kill $PID

echo "done"
