"""
User Session runtime context
"""

import logging
from contextvars import ContextVar

import fastapi

from . import common
from .server_auth_models import User

logger = logging.getLogger(__name__)

trace_tag = ContextVar("trace_tag")
ctx_user = ContextVar("ctx_user")


async def set_trace_tag(hs_ref_id: str = fastapi.Header(default=None)):
    """
    async! function to set context variable
    """
    value = hs_ref_id or f"self-{common.url_safe_id(n=8)}"
    trace_tag.set(value)


def set_user(user: User):
    ctx_user.set(user)
