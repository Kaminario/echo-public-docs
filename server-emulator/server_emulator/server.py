"""
Silk Instant Extract Server Imitation
"""

import asyncio

import fastapi
import uvicorn

from . import api, server_arguments, server_auth, server_logging, session_ctx

DEFAULT_KEEP_ALIVE_TIMEOUT = 60


async def _start() -> None:
    server_logging.configure_logging(context_vars=(session_ctx.trace_tag,))

    args = server_arguments.parse()

    app = fastapi.FastAPI(
        title="silk-server", description="Silk Instant Extract Server Imitation"
    )
    app.include_router(
        api.router,
        dependencies=[
            fastapi.Depends(session_ctx.set_trace_tag),
            fastapi.Depends(server_auth.require_user),
        ],
    )

    config = uvicorn.Config(
        app,
        host=args.host,
        port=args.port,
        timeout_keep_alive=DEFAULT_KEEP_ALIVE_TIMEOUT,
        access_log=False,
        log_config=uvicorn.config.LOGGING_CONFIG,
    )
    server = uvicorn.Server(config=config)
    await server.serve()


def main() -> None:
    asyncio.run(_start())
