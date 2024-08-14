"""
Server runtime context
"""

import logging
import time

from .. import api_models, common
from . import store
from .exceptions import HostAlreadyRegistered

logger = logging.getLogger(__name__)


def touch_last_seen(host):
    # touch last_seen_ts to simulate a heartbeat
    now = int(time.time())
    if host.last_seen_ts < now - 10:
        host.last_seen_ts = now - 1


def register_host(host_id: str, db_vendor: str):
    logger.info(f"Registering host. {host_id=}")
    if host_id in store.hosts:
        logger.info(f"Host already registered. {host_id=}")
        raise HostAlreadyRegistered(host_id)

    token_id = common.url_safe_id()
    host_name = f"host_{common.url_safe_id(5)}"

    store.hosts[host_id] = api_models.Host(
        host_id=host_id,
        db_vendor=db_vendor,
        last_seen_ts=int(time.time()),
        token=token_id,
        host_name=host_name,
        host_iqn=f"iqn.2009-01.com.kaminario:initiator.{host_name}",
        host_os="Windows",
        host_os_version="Windows 10",
        agent_version="0.1.0",
        cloud_vendor=api_models.Cloud.AZURE,
    )

    store.tokens[token_id] = api_models.Token(
        host_id=host_id,
        token=token_id,
        valid=True,
    )
    store.host_id2token_id[host_id] = token_id
    return token_id


def unregister_host(host_id: str) -> None:
    logger.info(f"Unregistering host. {host_id=}")
    try:
        token_id = store.host_id2token_id.pop(host_id)
        del store.hosts[host_id]
        del store.tokens[token_id]
        logger.info(f"Host unregistered. {host_id=}")
    except KeyError:
        logger.info(f"Host not found. {host_id=}. See as: already unregistered")


def get_host(host_id: str) -> api_models.Host:
    logger.info(f"Getting host. {host_id=}")
    host = store.hosts.get(host_id)
    if host:
        touch_last_seen(host)
    return host


def get_hosts() -> list[api_models.Host]:
    logger.info(f"Listing hosts")
    for host in store.hosts.values():
        touch_last_seen(host)
    return list(store.hosts.values())


def get_token(host_id: str) -> api_models.Token:
    logger.info(f"Getting token. {host_id=}")
    token_id = store.host_id2token_id.get(host_id)
    if token_id:
        return store.tokens.get(token_id)
    return None
