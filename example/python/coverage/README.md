# Test Coverage Suite

This test coverage suite validates Flex API endpoints.

## Prerequisites

- Python 3.x
- Virtual environment (recommended) with dependencies installed:
  ```bash
  python -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  ```

## Required Environment Variables

The following environment variables must be set before running the tests:

### Required
- `FLEX_TOKEN` - Bearer token for Flex API authentication
- `FLEX_IP` - Flex server IP address or hostname
- `HOST_NAME` - Host name/ID to use for tests (host_id and host_name are the same)
- `DB_NAME` - Database name to use for tests
- `DEST_HOST_NAME` - Destination host name/ID for clone/refresh tests
## Running Tests

### Setting Up Environment Variables

You can set environment variables manually or use the provided environment file:

```bash
export FLEX_TOKEN="your-token"
export FLEX_IP="your-ip-or-hostname"
export HOST_NAME="your-host-name"
export DB_NAME="your-database-name"
export DEST_HOST_NAME="destination-host-name"
```

### Run All Tests

```bash
./test-coverage.sh
```

### Run Individual Test

You can run individual test files directly:

```bash
# Single host tests
python coverage/test_topology.py
python coverage/test_snapshot.py --host-name "$HOST_NAME" --db-name "$DB_NAME"
python coverage/test_list_tasks.py --host-name "$HOST_NAME" --db-name "$DB_NAME"
python coverage/test_list_databases.py --host-name "$HOST_NAME"

# Two host tests
python coverage/test_clone_echo_db.py --source-host-name "$HOST_NAME" --dest-host-name "$DEST_HOST_NAME" --db-name "$DB_NAME"
python coverage/test_delete_echo_db.py --source-host-name "$HOST_NAME" --dest-host-name "$DEST_HOST_NAME" --db-name "$DB_NAME"
python coverage/test_clone_from_snapshot.py --source-host-name "$HOST_NAME" --dest-host-name "$DEST_HOST_NAME" --db-name "$DB_NAME"
python coverage/test_refresh_database.py --source-host-name "$HOST_NAME" --dest-host-name "$DEST_HOST_NAME" --db-name "$DB_NAME"
```

## Test Files

The test suite includes the following test files:

1. **test_topology.py** - Tests GET /api/echo/v1/topology endpoint
2. **test_snapshot.py** - Tests snapshot listing, creation, and deletion endpoints
3. **test_list_tasks.py** - Tests task listing endpoints
4. **test_list_databases.py** - Tests database listing endpoints
5. **test_clone_echo_db.py** - Tests echo DB clone from source and deletion
6. **test_clone_from_snapshot.py** - Tests clone from snapshot
7. **test_refresh_database.py** - Tests database refresh/replace
8. **clean.py** - Cleanup script to remove remaining test snapshots

## Test Behavior

Each test:
- Validates request payloads using `__validate` endpoints before executing operations
- Tests direct endpoints (`/api/ocie/v1/*`)
- Creates necessary resources (snapshots, echo DBs) for testing
- Cleans up created resources after testing
- Validates responses and error handling

## Output

The test script provides colored output:
- ✓ Green checkmarks indicate passed tests
- ✗ Red X marks indicate failed tests
- Yellow text indicates warnings or skipped tests

A summary is displayed at the end showing:
- Number of passed tests
- Number of failed tests
- List of failed test files (if any)

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed

## Notes

- Tests are independent and can be run individually
- Tests create temporary resources with prefixes like `test-`, `test-del-`, etc.
- Tests automatically clean up created resources, but manual cleanup may be needed if a test fails mid-execution
