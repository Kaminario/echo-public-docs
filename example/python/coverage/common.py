# Copyright (c) 2025 Silk Technologies, Inc.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import random
import sys
import time
from typing import Optional, Dict, Any, List

import requests

requests.packages.urllib3.disable_warnings()

# Import login functionality
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from login import ensure_token

# Environment Variables
FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")
FLEX_IP = os.getenv("FLEX_IP", "")


def exit_with_error(msg: str, **kwargs):
    """Print error message to stderr and exit with code 1."""
    print(msg, file=sys.stderr, **kwargs)
    sys.exit(1)


def _ensure_env():
    """Validate that FLEX_TOKEN and FLEX_IP environment variables are set.
    If FLEX_TOKEN is not set, prompt for login credentials."""
    global FLEX_TOKEN, FLEX_IP

    if not FLEX_IP:
        exit_with_error("FLEX_IP environment variable must be set.")

    # Check if token is set, if not, try to login
    if not FLEX_TOKEN:
        ensure_token()
        # Refresh FLEX_TOKEN from environment after login
        FLEX_TOKEN = os.getenv("FLEX_TOKEN", "")

    if not FLEX_TOKEN:
        exit_with_error("FLEX_TOKEN environment variable must be set.")


def _tracking_id() -> str:
    """Generate a random string [a-zA-Z0-9]{10} to track requests in Flex logs."""
    return "".join(
        random.choices(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=10
        )
    )


def _get_topology() -> List[Dict[str, Any]]:
    """Retrieve the full topology from the Flex API.

    Returns:
        List[Dict[str, Any]]: Topology data containing hosts and databases.
    """
    url = f"https://{FLEX_IP}/api/ocie/v1/topology"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
    }

    response = requests.get(url, verify=False, headers=headers)

    if response.status_code // 100 != 2:
        exit_with_error(
            f"Failed to get database topology. tracking_id: {tracking_id} Error: {response.status_code} {response.text}"
        )

    return response.json()


def _get_host_topology(host_name: str) -> Dict[str, Any]:
    """Get topology for a specific host by name (host_id and host_name are the same).

    Args:
        host_name: Host name/ID to find

    Returns:
        Dict containing host topology data

    Raises:
        SystemExit: If host not found
    """
    if not host_name:
        exit_with_error("host_name must be provided.")

    topology = _get_topology()

    for host_data in topology:
        if host_data["host"]["id"] == host_name or host_data["host"]["name"] == host_name:
            return host_data

    exit_with_error(f"Host '{host_name}' not found in topology.")


def _wait_for_task(task: Dict[str, Any], timeout: int = 300) -> tuple[bool, Dict[str, Any]]:
    """Poll the task API to check task completion.

    Args:
        task: The task data returned from the initial request
        timeout: Maximum time in seconds to wait for task completion

    Returns:
        tuple[bool, dict]: A boolean indicating success and the final task data.
    """
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": _tracking_id(),
        "Accept": "application/json",
    }

    start_time = time.time()

    while task["state"] == "running":
        if time.time() - start_time > timeout:
            exit_with_error(f"Task exceeded timeout of {timeout} seconds.")

        time.sleep(5)
        print(".", end="", flush=True)

        task_location = task.get("location")
        if not task_location:
            exit_with_error("Task missing 'location' field.")

        url = f"https://{FLEX_IP}{task_location}"
        response = requests.get(url, verify=False, headers=headers)

        if response.status_code // 100 == 2:
            task = response.json()
        else:
            exit_with_error(f"Failed to get task status: {response.status_code} {response.text}")

    print()  # Newline after dots
    # task states: "completed", "failed", "aborted"
    return task["state"] == "completed", task


def _make_request(
    method: str,
    endpoint: str,
    payload: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Make an API request to Flex using direct endpoints only.

    Args:
        method: HTTP method (GET, POST, DELETE, etc.)
        endpoint: API endpoint path (e.g., '/api/ocie/v1/topology')
        payload: Optional request payload for POST/DELETE requests

    Returns:
        Dict containing the JSON response
    """
    url = f"https://{FLEX_IP}{endpoint}"
    tracking_id = _tracking_id()
    headers = {
        "Authorization": f"Bearer {FLEX_TOKEN}",
        "hs-ref-id": tracking_id,
        "Accept": "application/json",
    }

    if payload:
        headers["Content-Type"] = "application/json"

    if method.upper() == "GET":
        response = requests.get(url, verify=False, headers=headers)
    elif method.upper() == "POST":
        response = requests.post(url, json=payload, verify=False, headers=headers)
    elif method.upper() == "DELETE":
        response = requests.delete(url, json=payload, verify=False, headers=headers)
    else:
        exit_with_error(f"Unsupported HTTP method: {method}")

    if response.status_code // 100 != 2:
        exit_with_error(
            f"API request failed. Method: {method}, URL: {url}, Status: {response.status_code}, Response: {response.text}"
        )

    return response.json()
