# Python Examples for Echo

## Setup environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Call script with --help to see usage examples.

For instance:

```bash
source .venv/bin/activate
python db_clone.py --help
```

## API Endpoints

The examples use the following API endpoints:

- **Host Management**: `/api/v1/hosts`
- **Echo Operations**: `/api/echo/v1/echo_dbs`
- **Snapshots**: `/api/echo/v1/db_snapshots`
- **Tasks**: `/api/echo/v1/tasks`
- **Topology**: `/api/echo/v1/topology`
