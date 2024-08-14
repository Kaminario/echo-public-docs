import logging
import sys
from contextvars import ContextVar
from typing import Any, Iterable, TextIO

import uvicorn


def render_contextvars(vars: Iterable[ContextVar]) -> str:
    ctx_items: list[str] = []
    for var in vars:
        try:
            ctx_items.append(f"{var.name}='{var.get()}'")
        except LookupError:
            # the context_var is not set
            continue
    return " ".join(ctx_items)


class Formatter(logging.Formatter):
    def __init__(
        self,
        fmt=None,
        datefmt=None,
        style="{",
        contextvars: Iterable[ContextVar] = (),
        **kwargs: Any,
    ):
        self.contextvars = contextvars
        super().__init__(fmt=fmt, datefmt=datefmt, style=style, **kwargs)

    def format(self, record):
        if self.contextvars:
            record.contextvars = render_contextvars(self.contextvars)
        else:
            record.contextvars = ""
        return super().format(record)


def _build_logging_configuration(
    fmt: str,
    datefmt: str,
    root_level: int,
    contextvars: Iterable[ContextVar],
    stream: TextIO,
):
    formatter = Formatter(fmt=fmt, datefmt=datefmt, contextvars=contextvars)
    conf = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "current": {
                "()": lambda: formatter,
            },
        },
        "handlers": {
            "console": {
                "level": "DEBUG",
                "class": "logging.StreamHandler",
                "formatter": "current",
                "stream": stream,
            }
        },
        "root": {
            "level": logging.getLevelName(root_level),
            "handlers": ["console"],
        },
    }
    return conf


def configure_logging(context_vars: list[ContextVar]):
    format = "{asctime}.{msecs:03.0f} - {levelname} ## {message} {contextvars}"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    # configure root logger
    conf = _build_logging_configuration(
        format, datefmt, logging.INFO, context_vars, stream=sys.stderr
    )
    logging.config.dictConfig(conf)
    uvicorn.config.LOGGING_CONFIG = conf
