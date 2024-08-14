#!/bin/bash

venv_dir=".venv"

# deactivate forign virtual environment if any
if [ -n "$VIRTUAL_ENV" ]; then
    echo "deactivate virtual environment [$VIRTUAL_ENV]"
    deactivate
fi

if [ ! -d "$venv_dir" ]; then
    echo "create virtual environment"
    python3.12 -m venv "$venv_dir"
else
    echo "virtual environment [$venv_dir] exists"
fi

if [ -z "$VIRTUAL_ENV" ]; then
    echo "activate virtual environment"
    source .venv/bin/activate
else
    echo "virtual environment [$VIRTUAL_ENV] activated"
fi

# install if required
command -v start-silk-server >/dev/null 2>&1 || { echo "installing silk-server"; pip install -e .; }

echo "start-silk-server"
start-silk-server
