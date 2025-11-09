# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import sys
import getpass
from typing import Optional

import requests

requests.packages.urllib3.disable_warnings()

# Environment Variables
FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
FLEX_IP = os.getenv("FLEX_IP", "")


def exit_with_error(msg: str, **kwargs):
    """Print error message to stderr and exit with code 1."""
    print(msg, file=sys.stderr, **kwargs)
    sys.exit(1)


def login(username: str, password: str) -> str:
    """Perform login and return the authentication token.

    Args:
        username: Username for authentication
        password: Password for authentication

    Returns:
        str: Authentication token

    Raises:
        SystemExit: If login fails
    """
    if not FLEX_IP:
        exit_with_error("FLEX_IP environment variable must be set.")

    # Try common login endpoints
    login_endpoints = [
        "/api/v1/auth/local/login",
    ]

    # Use form-urlencoded format (password first, then username as per the curl example)
    payload = f"password={password}&username={username}"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    last_error = None
    for endpoint in login_endpoints:
        url = f"https://{FLEX_IP}{endpoint}"
        try:
            response = requests.post(url, data=payload, verify=False, headers=headers)

            if response.status_code // 100 == 2:
                result = response.json()
                # Try common token field names
                token = result.get("token") or result.get("access_token") or result.get("accessToken")
                if token:
                    return token
                # If response is just a string token
                if isinstance(result, str):
                    return result
                # If token is in a nested structure
                if "data" in result and isinstance(result["data"], dict):
                    token = result["data"].get("token") or result["data"].get("access_token")
                    if token:
                        return token
            elif response.status_code == 404:
                # Endpoint doesn't exist, try next one
                continue
            else:
                last_error = f"Login failed with status {response.status_code}: {response.text}"
        except Exception as e:
            last_error = f"Login request failed: {str(e)}"
            continue

    if last_error:
        exit_with_error(f"Failed to login. {last_error}")
    else:
        exit_with_error("Failed to login. No valid login endpoint found.")


def ensure_token() -> str:
    """Check if FLEX_TOKEN is set, and if not, prompt for credentials and set it.

    This function will:
    1. Check if FLEX_TOKEN is already set
    2. If not set, prompt for username and password
    3. Perform login to get a token
    4. Set FLEX_TOKEN environment variable for future execution

    Returns:
        str: The token (empty string if already set, or the new token if login was performed)
    """
    global FLEX_TOKEN

    if FLEX_TOKEN:
        return ""

    if not FLEX_IP:
        exit_with_error("FLEX_IP environment variable must be set.")

    print("\nFLEX_TOKEN is not set. Please provide credentials to login.\n", file=sys.stderr)

    try:
        sys.stderr.write("Username: ")
        sys.stderr.flush()
        username = sys.stdin.readline().strip()
        password = getpass.getpass("Password: ")
    except KeyboardInterrupt:
        print("\nLogin cancelled.", file=sys.stderr)
        sys.exit(1)

    if not username or not password:
        exit_with_error("Username and password are required.")

    print("Logging in...", file=sys.stderr)
    token = login(username, password)

    # Set the token in the environment for future execution
    os.environ["FLEX_TOKEN"] = token
    FLEX_TOKEN = token

    print("Login successful. FLEX_TOKEN has been set.", file=sys.stderr)
    return token


if __name__ == "__main__":
    token = ensure_token()
    # If we got a token, output it in a format that can be sourced by shell scripts
    # This allows the shell script to export FLEX_TOKEN
    if token:
        # Output the export command that can be evaluated by the shell
        print(f'export FLEX_TOKEN="{token}"')
