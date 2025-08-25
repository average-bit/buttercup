from __future__ import annotations

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Optional
from nats.js.client import JetStreamContext
from buttercup.common.nats_datastructures import NatsBuildMap, NatsTaskRegistry
from buttercup.common.challenge_task import ChallengeTask
from buttercup.common.datastructures.msg_pb2 import BuildType, BuildOutput, POVReproduceRequest, POVReproduceResponse
from buttercup.common.nats_queues import NatsQueue, NatsQueueFactory, QueueNames, GroupNames
import buttercup.common.node_local as node_local
from buttercup.common.utils import serve_loop_async

logger = logging.getLogger(__name__)


@dataclass
class POVReproducer:
    jetstream: JetStreamContext
    sleep_time: float = 0.1
    max_retries: int = 10

    request_queue: NatsQueue[POVReproduceRequest] = field(init=False)
    response_queue: NatsQueue[POVReproduceResponse] = field(init=False)
    build_map: NatsBuildMap = field(init=False)
    registry: NatsTaskRegistry = field(init=False)

    async def __post_init__(self):
        queue_factory = NatsQueueFactory(self.jetstream.client, self.jetstream)
        self.request_queue = queue_factory.create(QueueNames.POV_REPRODUCER_REQUESTS, GroupNames.ORCHESTRATOR)
        await self.request_queue.__post_init__()
        self.response_queue = queue_factory.create(QueueNames.POV_REPRODUCER_RESPONSES)
        await self.response_queue.__post_init__()
        self.build_map = NatsBuildMap(self.jetstream)
        self.registry = NatsTaskRegistry(self.jetstream)

    async def serve_item(self) -> bool:
        item = await self.request_queue.pop()
        if item is None:
            return False

        entry = item.deserialized
        task_id: str = entry.task_id
        internal_patch_id: str = entry.internal_patch_id
        pov_path: str = entry.pov_path
        sanitizer: str = entry.sanitizer
        harness_name: str = entry.harness_name

        if await self.registry.should_stop_processing(task_id):
            logger.info("Task %s is cancelled or expired, will not reproduce POV.", task_id)
            await self.request_queue.ack_item(item)
            return False

        logger.info(f"Reproducing POV for {task_id} | {harness_name} | {pov_path}")

        builds = await self.build_map.get_builds(task_id, BuildType.PATCH)
        build_output_with_patch: Optional[BuildOutput] = next(
            (b for b in builds if b.sanitizer == sanitizer and b.internal_patch_id == internal_patch_id),
            None,
        )

        if build_output_with_patch is None:
            logger.warning(
                "No patched build output found for task %s. Will retry later.",
                task_id,
            )
            return False

        local_path: Path = node_local.make_locally_available(Path(pov_path))

        challenge_task_dir = ChallengeTask(read_only_task_dir=build_output_with_patch.task_dir)
        with challenge_task_dir.get_rw_copy(work_dir=node_local.scratch_path()) as task:
            info = task.reproduce_pov(harness_name, local_path)
            if not info.did_run():
                logger.warning(
                    f"Reproduce did not run for task %s. Will retry later. Output {info}",
                    task_id,
                )
                return False

            logger.debug(
                "stdout: %s, stderr: %s for task %s",
                info.command_result.output,
                info.command_result.error,
                task_id,
            )
            logger.info(f"POV {pov_path} for task: {task_id} crashed: {info.did_crash()}")

            response = POVReproduceResponse(
                request=entry,
                did_crash=info.did_crash(),
            )
            await self.response_queue.push(response)
            await self.request_queue.ack_item(item)

        return True

    async def serve(self) -> None:
        logger.info("Starting POV Reproducer")
        await serve_loop_async(self.serve_item, self.sleep_time)
