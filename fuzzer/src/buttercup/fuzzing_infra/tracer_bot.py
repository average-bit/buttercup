from buttercup.fuzzing_infra.settings import TracerSettings
from buttercup.fuzzing_infra.tracer_runner import TracerRunner
from buttercup.common.logger import setup_package_logger
import os
import logging
import nats
import asyncio
from nats.js.client import JetStreamContext
from buttercup.common.nats_queues import NatsQueue, NatsQueueFactory, QueueNames, GroupNames
from buttercup.common.datastructures.msg_pb2 import Crash, TracedCrash
from buttercup.common.nats_datastructures import NatsTaskRegistry as TaskRegistry
from pathlib import Path
from buttercup.common import stack_parsing
from buttercup.common.utils import serve_loop_async, setup_periodic_zombie_reaper
import buttercup.common.node_local as node_local
from buttercup.common.telemetry import init_telemetry

logger = logging.getLogger(__name__)


class TracerBot:
    def __init__(self, jetstream: JetStreamContext, seconds_sleep: int, wdir: str, python: str, max_tries: int):
        self.jetstream = jetstream
        self.seconds_sleep = seconds_sleep
        self.wdir = wdir
        self.python = python
        self.max_tries = max_tries
        self.queue: NatsQueue[Crash] | None = None
        self.output_q: NatsQueue[TracedCrash] | None = None
        self.registry: TaskRegistry | None = None

    async def __post_init__(self):
        queue_factory = NatsQueueFactory(self.jetstream.client, self.jetstream)
        self.queue = queue_factory.create(QueueNames.CRASH, GroupNames.TRACER_BOT)
        await self.queue.__post_init__()
        self.output_q = queue_factory.create(QueueNames.TRACED_VULNERABILITIES)
        await self.output_q.__post_init__()
        self.registry = TaskRegistry(self.jetstream)

    async def serve_item(self) -> bool:
        assert self.queue is not None
        assert self.output_q is not None
        assert self.registry is not None

        item = await self.queue.pop()
        if item is None:
            return False

        logger.info(f"Received tracer request for {item.deserialized.target.task_id}")
        if await self.registry.should_stop_processing(item.deserialized.target.task_id):
            logger.info(f"Task {item.deserialized.target.task_id} is cancelled or expired, skipping")
            await self.queue.ack_item(item)
            return True

        if await self.queue.times_delivered(item) > self.max_tries:
            logger.warning(f"Reached max tries for {item.deserialized.target.task_id}")
            await self.queue.ack_item(item)
            return True

        runner = TracerRunner(item.deserialized.target.task_id, self.wdir, self.jetstream)

        logger.info(f"Making locally available: {item.deserialized.crash_input_path}")
        local_path = node_local.make_locally_available(Path(item.deserialized.crash_input_path))

        tinfo = runner.run(
            item.deserialized.harness_name,
            local_path,
            item.deserialized.target.sanitizer,
        )
        if tinfo is None:
            logger.warning(f"No tracer info found for {item.deserialized.target.task_id}")
            return True

        if tinfo.is_valid:
            logger.info(f"Valid tracer info found for {item.deserialized.target.task_id}")
            prsed = stack_parsing.parse_stacktrace(tinfo.stacktrace)
            output = prsed.crash_stacktrace
            ntrace = output if output is not None and len(output) > 0 else tinfo.stacktrace
            await self.output_q.push(
                TracedCrash(
                    crash=item.deserialized,
                    tracer_stacktrace=ntrace,
                )
            )

        logger.info(f"Acknowledging tracer request for {item.deserialized.target.task_id}")
        await self.queue.ack_item(item)
        return True

    async def run(self) -> None:
        await serve_loop_async(self.serve_item, self.seconds_sleep)


async def main() -> None:
    args = TracerSettings()

    setup_package_logger("tracer-bot", __name__, "DEBUG", None)
    init_telemetry("tracer-bot")

    setup_periodic_zombie_reaper()

    os.makedirs(args.wdir, exist_ok=True)
    logger.info(f"Starting tracer-bot (wdir: {args.wdir})")

    nc = await nats.connect(args.nats_url)
    js = nc.jetstream()
    seconds_sleep = args.timer // 1000
    tracer_bot = TracerBot(js, seconds_sleep, args.wdir, args.python, args.max_tries)
    await tracer_bot.__post_init__()
    await tracer_bot.run()
    await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
