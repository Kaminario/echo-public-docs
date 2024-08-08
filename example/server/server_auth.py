from typing import Dict, Optional

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import server_error_responses, session_ctx
from .hints import TOKEN_ID
from .server_auth_models import User

auth_users: Dict[TOKEN_ID, User] = {
    "1111": User(name="legitimate-user"),
    "2222": User(name="another-legitimate-user"),
}

security = HTTPBearer()


async def require_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
):
    if not auth:
        raise server_error_responses.HTTPUnauthorizedError()

    user = auth_users.get(auth.credentials)
    if not user:
        raise server_error_responses.HTTPUnauthorizedError()
    session_ctx.set_user(user)
