#!/bin/bash

# activate env if not already activated

if [ -z "$VIRTUAL_ENV" ]; then
    echo "activate virtual environment"
    source .venv/bin/activate
fi

echo "start silk server"
start-silk-server
