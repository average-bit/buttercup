import logging
from typing import Any
from dataclasses import dataclass, field
from buttercup.common.nats_queues import (
    NatsQueue,
    NatsQueueFactory,
    QueueNames,
    GroupNames,
)
from buttercup.program_model.codequery import CodeQueryPersistent
from buttercup.common.datastructures.msg_pb2 import IndexRequest, IndexOutput
from buttercup.common.challenge_task import ChallengeTask
from buttercup.common.nats_datastructures import NatsTaskRegistry as TaskRegistry
from buttercup.common.utils import serve_loop_async
from pathlib import Path
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from nats.js.client import JetStreamContext
import buttercup.common.node_local as node_local
from buttercup.common.telemetry import set_crs_attributes, CRSActionCategory

logger = logging.getLogger(__name__)


@dataclass
class ProgramModel:
    sleep_time: float = 1.0
    jetstream: JetStreamContext | None = None
    task_queue: NatsQueue[IndexRequest] | None = field(init=False, default=None)
    output_queue: NatsQueue[IndexOutput] | None = field(init=False, default=None)
    registry: TaskRegistry | None = field(init=False, default=None)
    wdir: Path | None = None
    python: str | None = None
    allow_pull: bool = True

    async def __post_init__(self) -> None:
        if self.wdir is not None:
            self.wdir = Path(self.wdir).resolve()

        if self.jetstream is not None:
            logger.debug("Using NATS for task queues")
            queue_factory = NatsQueueFactory(self.jetstream.client, self.jetstream)
            self.task_queue = queue_factory.create(QueueNames.INDEX, GroupNames.INDEX)
            await self.task_queue.__post_init__()
            self.output_queue = queue_factory.create(QueueNames.INDEX_OUTPUT)
            await self.output_queue.__post_init__()
            self.registry = TaskRegistry(self.jetstream)

    def __enter__(self):
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        pass

    def process_task_codequery(self, args: IndexRequest) -> bool:
        try:
            logger.info(
                f"Processing task {args.package_name}/{args.task_id}/{args.task_dir} with codequery"
            )
            challenge = ChallengeTask(
                read_only_task_dir=args.task_dir,
                python_path=self.python,
            )
            with challenge.get_rw_copy(work_dir=self.wdir) as local_challenge:
                logger.debug(f"Applying diff for {args.task_id}")
                if not local_challenge.apply_patch_diff():
                    logger.debug(f"No diffs for {args.task_id}")

                if self.wdir is None:
                    raise ValueError("Work directory is not initialized")

                tracer = trace.get_tracer(__name__)
                with tracer.start_as_current_span("index_task_with_codequery") as span:
                    set_crs_attributes(
                        span,
                        crs_action_category=CRSActionCategory.PROGRAM_ANALYSIS,
                        crs_action_name="index_task_with_codequery",
                        task_metadata=dict(challenge.task_meta.metadata),
                    )
                    cqp = CodeQueryPersistent(local_challenge, work_dir=self.wdir)
                    logger.info(
                        f"Successfully processed task {args.package_name}/{args.task_id}/{args.task_dir} with codequery"
                    )
                    span.set_status(Status(StatusCode.OK))
                node_local.dir_to_remote_archive(cqp.challenge.task_dir)
            return True
        except Exception as e:
            logger.exception(f"Failed to process task {args.task_id}: {e}")
            return False

    def process_task(self, args: IndexRequest) -> bool:
        logger.info(
            f"Processing task {args.package_name}/{args.task_id}/{args.task_dir}"
        )
        return self.process_task_codequery(args)

    async def serve_item(self) -> bool:
        if self.task_queue is None:
            raise ValueError("Task queue is not initialized")
        rq_item = await self.task_queue.pop()
        if rq_item is None:
            return False

        task_index: IndexRequest = rq_item.deserialized

        if self.registry is not None and await self.registry.should_stop_processing(
            task_index.task_id
        ):
            logger.debug(f"Task {task_index.task_id} is cancelled or expired, skipping")
            await self.task_queue.ack_item(rq_item)
            return True

        success = self.process_task(task_index)

        if success:
            if self.output_queue is None:
                raise ValueError("Output queue is not initialized")
            await self.output_queue.push(
                IndexOutput(
                    build_type=task_index.build_type,
                    package_name=task_index.package_name,
                    sanitizer=task_index.sanitizer,
                    task_dir=task_index.task_dir,
                    task_id=task_index.task_id,
                )
            )
            await self.task_queue.ack_item(rq_item)
            logger.info(
                f"Successfully processed task {task_index.package_name}/{task_index.task_id}/{task_index.task_dir}"
            )
        else:
            logger.error(f"Failed to process task {task_index.task_id}")

        return True

    async def serve(self) -> None:
        if self.task_queue is None or self.output_queue is None:
            raise ValueError("Queues are not initialized")

        logger.debug("Starting indexing service")
        await serve_loop_async(self.serve_item, self.sleep_time)
