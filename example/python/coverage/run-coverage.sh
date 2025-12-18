#!/bin/bash

# Test Coverage Script
# Validates all required environment variables, then runs all test files
# Tests are organized by version: all v1 tests run first, then all v2 tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory where this script is located and change to it
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if FLEX_IP is set first (required for login)
if [ -z "$FLEX_IP" ]; then
    echo -e "${RED}Error: FLEX_IP environment variable is not set${NC}" >&2
    echo -e "${YELLOW}Please set FLEX_IP before running tests:${NC}" >&2
    echo -e "${YELLOW}  export FLEX_IP=\"your-flex-server-ip\"${NC}" >&2
    exit 1
fi

# Check if FLEX_TOKEN is set, if not, run login.py
if [ -z "$FLEX_TOKEN" ]; then
    echo -e "${YELLOW}FLEX_TOKEN is not set. Please login...${NC}"
    echo ""

    # Run login.py interactively with proper stdin/stderr/stdout handling
    # Redirect stderr to /dev/tty so prompts appear on terminal
    # Capture only stdout which contains the export command
    LOGIN_RESULT=$(python login.py </dev/tty 2>/dev/tty)
    LOGIN_EXIT=$?

    if [ $LOGIN_EXIT -ne 0 ]; then
        echo -e "${RED}Error: Login failed${NC}" >&2
        exit 1
    fi

    # Evaluate the export command
    if [ -n "$LOGIN_RESULT" ]; then
        eval "$LOGIN_RESULT"
    fi

    if [ -z "$FLEX_TOKEN" ]; then
        echo -e "${RED}Error: Failed to set FLEX_TOKEN after login${NC}" >&2
        exit 1
    fi

    echo ""
    echo -e "${GREEN}Login successful!${NC}"
    echo ""
fi

# Check if HOST_NAME is set
if [ -z "$HOST_NAME" ]; then
    echo -e "${RED}Error: HOST_NAME environment variable is not set${NC}" >&2
    exit 1
fi

# Check if DB_NAME is set
if [ -z "$DB_NAME" ]; then
    echo -e "${RED}Error: DB_NAME environment variable is not set${NC}" >&2
    exit 1
fi

# Check if DEST_HOST_NAME is set
if [ -z "$DEST_HOST_NAME" ]; then
    echo -e "${RED}Error: DEST_HOST_NAME environment variable is not set${NC}" >&2
    exit 1
fi

echo -e "${GREEN}Environment variables validated${NC}"
echo -e "${GREEN}  FLEX_TOKEN: set${NC}"
echo -e "${GREEN}  FLEX_IP: $FLEX_IP${NC}"
echo -e "${GREEN}  HOST_NAME: $HOST_NAME${NC}"
echo -e "${GREEN}  DB_NAME: $DB_NAME${NC}"
echo -e "${GREEN}  DEST_HOST_NAME: $DEST_HOST_NAME${NC}"
echo ""

# Run tests (direct /api/echo/v1/ endpoints)
echo -e "${YELLOW}Running API Tests (/api/echo/v1/)...${NC}"
echo ""

echo -e "${YELLOW}Running test_snapshot.py...${NC}"
python test_snapshot.py --host-name "$HOST_NAME" --db-name "$DB_NAME" || exit 1
echo ""

echo -e "${YELLOW}Running test_list_tasks.py...${NC}"
python test_list_tasks.py --host-name "$HOST_NAME" --db-name "$DB_NAME" || exit 1
echo ""

echo -e "${YELLOW}Running test_list_databases.py...${NC}"
python test_list_databases.py --host-name "$HOST_NAME" || exit 1
echo ""

echo -e "${YELLOW}Running test_clone_echo_db.py...${NC}"
python test_clone_echo_db.py --source-host-name "$HOST_NAME" --dest-host-name "$DEST_HOST_NAME" --db-name "$DB_NAME" || exit 1
echo ""

echo -e "${YELLOW}Running test_clone_from_snapshot.py...${NC}"
python test_clone_from_snapshot.py --source-host-name "$HOST_NAME" --dest-host-name "$DEST_HOST_NAME" --db-name "$DB_NAME" || exit 1
echo ""

echo -e "${YELLOW}Running test_refresh_database.py...${NC}"
python test_refresh_database.py --source-host-name "$HOST_NAME" --dest-host-name "$DEST_HOST_NAME" --db-name "$DB_NAME" || exit 1
echo ""

echo -e "${GREEN}All tests passed!${NC}"
exit 0
