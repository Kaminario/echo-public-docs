"""
Server runtime context
"""


class HostAlreadyRegistered(Exception):
    def __init__(self, host_id):
        self.host_id = host_id
        super().__init__(f"Host already registered: {host_id}")


class RequestIdConflict(Exception):
    def __init__(self, request_id):
        self.host_id = request_id
        super().__init__(f"Request Id Conflict: {request_id}")
