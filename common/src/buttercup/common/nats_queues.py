from __future__ import annotations

from dataclasses import dataclass, field
from nats.aio.client import Client as NATS
from nats.js.client import JetStreamContext
from nats.aio.msg import Msg
from google.protobuf.message import Message
from functools import wraps
from buttercup.common.datastructures.msg_pb2 import (
    BuildRequest,
    BuildOutput,
    Crash,
    TaskDownload,
    TaskReady,
    TaskDelete,
    Patch,
    ConfirmedVulnerability,
    IndexRequest,
    IndexOutput,
    TracedCrash,
    POVReproduceRequest,
    POVReproduceResponse,
)
import logging
from typing import Type, Generic, TypeVar, Literal, overload, Callable, cast
import uuid
import os
from enum import Enum
from typing import Any
import asyncio


TIMES_DELIVERED_FIELD = "times_delivered"

F = TypeVar("F", bound=Callable[..., Any])


class QueueNames(str, Enum):
    BUILD = "fuzzer_build_queue"
    BUILD_OUTPUT = "fuzzer_build_output_queue"
    CRASH = "fuzzer_crash_queue"
    CONFIRMED_VULNERABILITIES = "confirmed_vulnerabilities_queue"
    DOWNLOAD_TASKS = "orchestrator_download_tasks_queue"
    READY_TASKS = "tasks_ready_queue"
    DELETE_TASK = "orchestrator_delete_task_queue"
    PATCHES = "patches_queue"
    INDEX = "index_queue"
    INDEX_OUTPUT = "index_output_queue"
    TRACED_VULNERABILITIES = "traced_vulnerabilities_queue"
    POV_REPRODUCER_REQUESTS = "pov_reproducer_requests_queue"
    POV_REPRODUCER_RESPONSES = "pov_reproducer_responses_queue"


class GroupNames(str, Enum):
    BUILDER_BOT = "build_bot_consumers"
    ORCHESTRATOR = "orchestrator_group"
    PATCHER = "patcher_group"
    INDEX = "index_group"
    TRACER_BOT = "tracer_bot_group"


class HashNames(str, Enum):
    TASKS_REGISTRY = "tasks_registry"


BUILD_TASK_TIMEOUT_MS = int(os.getenv("BUILD_TASK_TIMEOUT_MS", 15 * 60 * 1000))
BUILD_OUTPUT_TASK_TIMEOUT_MS = int(os.getenv("BUILD_OUTPUT_TASK_TIMEOUT_MS", 3 * 60 * 1000))
DOWNLOAD_TASK_TIMEOUT_MS = int(os.getenv("DOWNLOAD_TASK_TIMEOUT_MS", 10 * 60 * 1000))
READY_TASK_TIMEOUT_MS = int(os.getenv("READY_TASK_TIMEOUT_MS", 3 * 60 * 1000))
DELETE_TASK_TIMEOUT_MS = int(os.getenv("DELETE_TASK_TIMEOUT_MS", 5 * 60 * 1000))
CRASH_TASK_TIMEOUT_MS = int(os.getenv("CRASH_TASK_TIMEOUT_MS", 4 * 60 * 1000))
PATCH_TASK_TIMEOUT_MS = int(os.getenv("PATCH_TASK_TIMEOUT_MS", 10 * 60 * 1000))
CONFIRMED_VULNERABILITIES_TASK_TIMEOUT_MS = int(os.getenv("CONFIRMED_VULNERABILITIES_TASK_TIMEOUT_MS", 10 * 60 * 1000))
INDEX_TASK_TIMEOUT_MS = int(os.getenv("INDEX_TASK_TIMEOUT_MS", 30 * 60 * 1000))
INDEX_OUTPUT_TASK_TIMEOUT_MS = int(os.getenv("INDEX_OUTPUT_TASK_TIMEOUT_MS", 3 * 60 * 1000))
TRACED_VULNERABILITIES_TASK_TIMEOUT_MS = int(os.getenv("TRACED_VULNERABILITIES_TASK_TIMEOUT_MS", 10 * 60 * 1000))
POV_REPRODUCER_REQUESTS_TASK_TIMEOUT_MS = int(os.getenv("POV_REPRODUCER_REQUESTS_TASK_TIMEOUT_MS", 10 * 60 * 1000))
POV_REPRODUCER_RESPONSES_TASK_TIMEOUT_MS = int(os.getenv("POV_REPRODUCER_RESPONSES_TASK_TIMEOUT_MS", 10 * 60 * 1000))

logger = logging.getLogger(__name__)


# Type variable for protobuf Message subclasses
# Used for type-hinting of reliable queue items
MsgType = TypeVar("MsgType", bound=Message)


@dataclass
class NQItem(Generic[MsgType]):
    """
    A single item in a NATS queue.
    """

    item: Msg
    deserialized: MsgType

    def __post_init__(self):
        # The `item_id` is used for acknowledging the message. In NATS, the message
        # object itself is used for acknowledgment, so we store the whole message.
        self.item_id = self.item.sid


@dataclass
class NatsQueue(Generic[MsgType]):
    """
    A queue that is reliable and can be used to process tasks in a distributed environment using NATS.
    """

    nats: NATS
    jetstream: JetStreamContext
    queue_name: str
    msg_builder: Type[MsgType]
    group_name: str | None = None
    task_timeout_ms: int = 180000
    reader_name: str | None = None
    block_time: int | None = 200
    consumer: Any = field(init=False)

    async def init_consumer(self) -> None:
        if self.reader_name is None:
            self.reader_name = f"rqueue_{str(uuid.uuid4())}"

        try:
            await self.jetstream.add_stream(name=self.queue_name, subjects=[self.queue_name])
        except Exception:
            pass

        if self.group_name:
            try:
                self.consumer = await self.jetstream.consumer_info(self.queue_name, self.group_name)
            except Exception:
                self.consumer = await self.jetstream.add_consumer(self.queue_name, durable_name=self.group_name)

    async def size(self) -> int:
        stream_state = await self.jetstream.stream_info(self.queue_name)
        return stream_state.state.messages

    async def push(self, item: MsgType) -> None:
        bts = item.SerializeToString()
        await self.jetstream.publish(self.queue_name, bts)

    @staticmethod
    def _ensure_group_name(func: F) -> F:
        @wraps(func)
        def wrapper(self: NatsQueue[MsgType], *args: Any, **kwargs: Any) -> Any:
            if self.group_name is None:
                raise ValueError("group_name must be set for this operation")

            return func(self, *args, **kwargs)

        return cast(F, wrapper)

    @_ensure_group_name
    async def pop(self) -> NQItem[MsgType] | None:
        assert self.group_name
        assert self.reader_name

        try:
            msgs = await self.consumer.fetch(batch=1, timeout=self.block_time / 1000 if self.block_time else 0)
            msg = msgs[0]
            # Create and parse protobuf message
            deserialized_msg = self.msg_builder()
            deserialized_msg.ParseFromString(msg.data)
            return NQItem[MsgType](item=msg, deserialized=deserialized_msg)
        except (asyncio.TimeoutError, IndexError):
            return None

    @_ensure_group_name
    async def ack_item(self, item: NQItem[MsgType]) -> None:
        await item.item.ack()

    @_ensure_group_name
    async def times_delivered(self, item: NQItem[MsgType]) -> int:
        return item.item.metadata.num_delivered

    @_ensure_group_name
    async def claim_item(self, item: NQItem[MsgType]) -> None:
        # NATS doesn't have an explicit "claim" operation like Redis.
        # The act of pulling a message and not acknowledging it makes it
        # available for redelivery after the ack_wait timeout.
        # We can simulate a claim by not acknowledging the message.
        pass


@dataclass
class QueueConfig:
    queue_name: QueueNames
    msg_builder: Type
    task_timeout_ms: int
    group_names: list[GroupNames] = field(default_factory=list)


@dataclass
class NatsQueueFactory:
    """Factory for creating common reliable queues using NATS"""

    nats: NATS
    jetstream: JetStreamContext
    _config: dict[QueueNames, QueueConfig] = field(
        default_factory=lambda: {
            QueueNames.BUILD: QueueConfig(
                QueueNames.BUILD,
                BuildRequest,
                BUILD_TASK_TIMEOUT_MS,
                [GroupNames.BUILDER_BOT],
            ),
            QueueNames.BUILD_OUTPUT: QueueConfig(
                QueueNames.BUILD_OUTPUT,
                BuildOutput,
                BUILD_OUTPUT_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.DOWNLOAD_TASKS: QueueConfig(
                QueueNames.DOWNLOAD_TASKS,
                TaskDownload,
                DOWNLOAD_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.READY_TASKS: QueueConfig(
                QueueNames.READY_TASKS,
                TaskReady,
                READY_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.CRASH: QueueConfig(
                QueueNames.CRASH,
                Crash,
                CRASH_TASK_TIMEOUT_MS,
                [GroupNames.TRACER_BOT],
            ),
            QueueNames.TRACED_VULNERABILITIES: QueueConfig(
                QueueNames.TRACED_VULNERABILITIES,
                TracedCrash,
                TRACED_VULNERABILITIES_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.CONFIRMED_VULNERABILITIES: QueueConfig(
                QueueNames.CONFIRMED_VULNERABILITIES,
                ConfirmedVulnerability,
                CONFIRMED_VULNERABILITIES_TASK_TIMEOUT_MS,
                [GroupNames.PATCHER],
            ),
            QueueNames.DELETE_TASK: QueueConfig(
                QueueNames.DELETE_TASK,
                TaskDelete,
                DELETE_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.PATCHES: QueueConfig(
                QueueNames.PATCHES,
                Patch,
                PATCH_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.INDEX: QueueConfig(
                QueueNames.INDEX,
                IndexRequest,
                INDEX_TASK_TIMEOUT_MS,
                [GroupNames.INDEX],
            ),
            QueueNames.INDEX_OUTPUT: QueueConfig(
                QueueNames.INDEX_OUTPUT,
                IndexOutput,
                INDEX_OUTPUT_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.POV_REPRODUCER_REQUESTS: QueueConfig(
                QueueNames.POV_REPRODUCER_REQUESTS,
                POVReproduceRequest,
                POV_REPRODUCER_REQUESTS_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
            QueueNames.POV_REPRODUCER_RESPONSES: QueueConfig(
                QueueNames.POV_REPRODUCER_RESPONSES,
                POVReproduceResponse,
                POV_REPRODUCER_RESPONSES_TASK_TIMEOUT_MS,
                [GroupNames.ORCHESTRATOR],
            ),
        }
    )

    @overload
    def create(
        self, queue_name: Literal[QueueNames.BUILD], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[BuildRequest]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.BUILD_OUTPUT], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[BuildOutput]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.DOWNLOAD_TASKS], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[TaskDownload]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.READY_TASKS], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[TaskReady]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.CRASH], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[Crash]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.TRACED_VULNERABILITIES], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[TracedCrash]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.CONFIRMED_VULNERABILITIES], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[ConfirmedVulnerability]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.DELETE_TASK], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[TaskDelete]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.PATCHES], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[Patch]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.INDEX], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[IndexRequest]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.INDEX_OUTPUT], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[IndexOutput]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.POV_REPRODUCER_REQUESTS], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[POVReproduceRequest]: ...

    @overload
    def create(
        self, queue_name: Literal[QueueNames.POV_REPRODUCER_RESPONSES], group_name: GroupNames, **kwargs: Any
    ) -> NatsQueue[POVReproduceResponse]: ...

    @overload
    def create(
        self, queue_name: QueueNames, group_name: GroupNames | None = None, **kwargs: Any
    ) -> NatsQueue[MsgType]: ...

    def create(self, queue_name: QueueNames, group_name: GroupNames | None = None, **kwargs: Any) -> NatsQueue[MsgType]:
        if queue_name not in self._config:
            raise ValueError(f"Invalid queue name: {queue_name}")

        config = self._config[queue_name]

        if group_name is not None and group_name not in config.group_names:
            raise ValueError(f"Invalid group name: {group_name}")

        queue: NatsQueue[MsgType] = NatsQueue(
            nats=self.nats,
            jetstream=self.jetstream,
            queue_name=config.queue_name,
            msg_builder=config.msg_builder,
            task_timeout_ms=config.task_timeout_ms,
            group_name=group_name,
            **kwargs,
        )
        return queue
