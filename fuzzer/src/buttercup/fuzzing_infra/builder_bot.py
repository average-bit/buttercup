from buttercup.common.nats_queues import QueueNames, GroupNames
from nats.js.client import JetStreamContext
import nats
import asyncio
from buttercup.common.nats_queues import NatsQueueFactory, NatsQueue
from buttercup.common.datastructures.msg_pb2 import BuildType, BuildOutput, BuildRequest
from buttercup.common.logger import setup_package_logger
from dataclasses import dataclass, field
import logging
import tempfile
from buttercup.common.utils import serve_loop_async
from buttercup.common.challenge_task import ChallengeTask, ChallengeTaskError
from pathlib import Path
from buttercup.fuzzing_infra.settings import BuilderBotSettings
import buttercup.common.node_local as node_local
from buttercup.common.telemetry import init_telemetry
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from buttercup.common.telemetry import set_crs_attributes, CRSActionCategory
from buttercup.common.nats_datastructures import NatsTaskRegistry as TaskRegistry

logger = logging.getLogger(__name__)


@dataclass
class BuilderBot:
    jetstream: JetStreamContext
    seconds_sleep: float
    allow_caching: bool
    allow_pull: bool
    python: str
    wdir: str
    max_tries: int = 3

    _build_requests_queue: NatsQueue[BuildRequest] = field(init=False)
    _build_outputs_queue: NatsQueue[BuildOutput] = field(init=False)
    _registry: TaskRegistry = field(init=False)

    async def __post_init__(self) -> None:
        queue_factory = NatsQueueFactory(self.jetstream.client, self.jetstream)
        self._build_requests_queue = queue_factory.create(QueueNames.BUILD, GroupNames.BUILDER_BOT)
        await self._build_requests_queue.__post_init__()
        self._build_outputs_queue = queue_factory.create(QueueNames.BUILD_OUTPUT)
        await self._build_outputs_queue.__post_init__()
        self._registry = TaskRegistry(self.jetstream)

    def _apply_challenge_diff(self, task: ChallengeTask, msg: BuildRequest) -> bool:
        if msg.apply_diff and task.is_delta_mode():
            logger.info(
                f"Applying diff for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
            )
            try:
                res = task.apply_patch_diff()
                if not res:
                    logger.warning(
                        f"No diffs for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
                    )
                    return False
            except ChallengeTaskError:
                logger.exception(
                    "Failed to apply diff for %s | %s | %s | %s | diff %s",
                    msg.task_id,
                    msg.engine,
                    msg.sanitizer,
                    BuildType.Name(msg.build_type),
                    msg.apply_diff,
                )
                return False
        return True

    def _apply_patch(self, task: ChallengeTask, msg: BuildRequest) -> bool:
        if msg.patch and msg.internal_patch_id:
            with tempfile.NamedTemporaryFile(mode="w+") as patch_file:
                patch_file.write(msg.patch)
                patch_file.flush()
                logger.debug("Patch written to %s", patch_file.name)

                logger.info(
                    f"Applying patch for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
                )
                try:
                    res = task.apply_patch_diff(Path(patch_file.name))
                    if not res:
                        logger.info(
                            f"Failed to apply patch for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
                        )
                        return False
                except ChallengeTaskError:
                    logger.exception(
                        "Failed to apply patch for %s | %s | %s | %s | diff %s",
                        msg.task_id,
                        msg.engine,
                        msg.sanitizer,
                        BuildType.Name(msg.build_type),
                        msg.apply_diff,
                    )
                    return False
        return True

    async def serve_item(self) -> bool:
        rqit = await self._build_requests_queue.pop()
        if rqit is None:
            return False

        msg = rqit.deserialized
        logger.info(
            f"Received build request for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
        )

        if await self._registry.should_stop_processing(msg.task_id):
            logger.info(f"Skipping expired or cancelled task {msg.task_id}")
            await self._build_requests_queue.ack_item(rqit)
            return False

        task_dir = Path(msg.task_dir)
        if self.allow_caching:
            origin_task = ChallengeTask(
                task_dir,
                python_path=self.python,
                local_task_dir=task_dir,
            )
        else:
            origin_task = ChallengeTask(
                task_dir,
                python_path=self.python,
            )

        with origin_task.get_rw_copy(work_dir=self.wdir) as task:
            if not self._apply_challenge_diff(task, msg):
                if await self._build_requests_queue.times_delivered(rqit) > self.max_tries:
                    logger.error(
                        f"Max tries reached for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
                    )
                    await self._build_requests_queue.ack_item(rqit)
                return True

            if not self._apply_patch(task, msg):
                if await self._build_requests_queue.times_delivered(rqit) > self.max_tries:
                    logger.error(
                        f"Max tries reached for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff} | patch {msg.internal_patch_id}"
                    )
                    await self._build_requests_queue.ack_item(rqit)
                return True

            tracer = trace.get_tracer(__name__)
            with tracer.start_as_current_span("build_fuzzers_with_cache") as span:
                set_crs_attributes(
                    span,
                    crs_action_category=CRSActionCategory.BUILDING,
                    crs_action_name="build_fuzzers_with_cache",
                    task_metadata=dict(origin_task.task_meta.metadata),
                )
                res = task.build_fuzzers_with_cache(
                    engine=msg.engine, sanitizer=msg.sanitizer, pull_latest_base_image=self.allow_pull
                )

                if not res.success:
                    logger.error(
                        f"Could not build fuzzer {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
                    )
                    span.set_status(Status(StatusCode.ERROR))
                    return True
                span.set_status(Status(StatusCode.OK))

            task.commit()
            logger.info(
                f"Pushing build output for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
            )
            node_local.dir_to_remote_archive(task.task_dir)
            await self._build_outputs_queue.push(
                BuildOutput(
                    engine=msg.engine,
                    sanitizer=msg.sanitizer,
                    task_dir=str(task.task_dir),
                    task_id=msg.task_id,
                    build_type=msg.build_type,
                    apply_diff=msg.apply_diff,
                    internal_patch_id=msg.internal_patch_id,
                )
            )
            logger.info(
                f"Acked build request for {msg.task_id} | {msg.engine} | {msg.sanitizer} | {BuildType.Name(msg.build_type)} | diff {msg.apply_diff}"
            )
            await self._build_requests_queue.ack_item(rqit)
            return True

    async def run(self) -> None:
        await serve_loop_async(self.serve_item, self.seconds_sleep)


def main() -> None:
    args = BuilderBotSettings()

    setup_package_logger("builder-bot", __name__, args.log_level, args.log_max_line_length)
    init_telemetry("builder-bot")

    logger.info(f"Starting builder bot ({args.wdir})")

    async def _main():
        nc = await nats.connect(args.nats_url)
        js = nc.jetstream()
        seconds = float(args.timer) // 1000.0
        builder_bot = BuilderBot(
            js,
            seconds,
            args.allow_caching,
            args.allow_pull,
            args.python,
            args.wdir,
        )
        await builder_bot.__post_init__()
        await builder_bot.run()
        await nc.close()

    asyncio.run(_main())


if __name__ == "__main__":
    main()
