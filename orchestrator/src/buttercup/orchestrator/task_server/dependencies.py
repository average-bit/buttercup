import logging
import nats
from nats.js.client import JetStreamContext
from functools import lru_cache
from buttercup.orchestrator.task_server.config import TaskServerSettings
from buttercup.common.nats_queues import NatsQueue, QueueNames, NatsQueueFactory
from buttercup.common.nats_datastructures import NatsSARIFStore

logger = logging.getLogger(__name__)


@lru_cache
def get_settings() -> TaskServerSettings:
    return TaskServerSettings()


@lru_cache
async def get_nats_client():
    logger.debug(f"Connecting to NATS at {get_settings().nats_url}")
    return await nats.connect(get_settings().nats_url)


@lru_cache
async def get_jetstream() -> JetStreamContext:
    nats_client = await get_nats_client()
    return nats_client.jetstream()


@lru_cache
async def get_task_queue() -> NatsQueue:
    logger.debug(f"Connecting to task queue at {QueueNames.DOWNLOAD_TASKS}")
    nats_client = await get_nats_client()
    jetstream = await get_jetstream()
    queue = NatsQueueFactory(nats_client, jetstream).create(QueueNames.DOWNLOAD_TASKS)
    await queue.__post_init__()
    return queue


@lru_cache
async def get_delete_task_queue() -> NatsQueue:
    logger.debug(f"Connecting to delete task queue at {QueueNames.DELETE_TASK}")
    nats_client = await get_nats_client()
    jetstream = await get_jetstream()
    queue = NatsQueueFactory(nats_client, jetstream).create(QueueNames.DELETE_TASK)
    await queue.__post_init__()
    return queue


async def get_sarif_store() -> NatsSARIFStore:
    jetstream = await get_jetstream()
    return NatsSARIFStore(jetstream)
