#!/bin/bash

echo "create and activate virtual environment"
python3.12 -m venv .venv
source .venv/bin/activate
echo "install echo-server"
pip install -e .
