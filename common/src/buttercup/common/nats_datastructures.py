from __future__ import annotations

import json
from typing import Any, List
from nats.js.client import JetStreamContext
from nats.js.kv import KeyValue
from google.protobuf.message import Message
from typing import Type, Generic, TypeVar
from buttercup.common.datastructures.msg_pb2 import (
    Task,
    WeightedHarness,
    FunctionCoverage,
    BuildOutput,
    BuildType,
    POVReproduceRequest,
    POVReproduceResponse,
)
from buttercup.common.sarif_store import SARIFBroadcastDetail
from dataclasses import dataclass

MsgType = TypeVar("MsgType", bound=Message)


class NatsMap(Generic[MsgType]):
    """
    A map-like data structure backed by a NATS Key-Value Store.
    """

    def __init__(self, jetstream: JetStreamContext, bucket_name: str, msg_builder: Type[MsgType]):
        self.jetstream = jetstream
        self.bucket_name = bucket_name
        self.msg_builder = msg_builder
        self.kv_store: KeyValue | None = None

    async def _get_store(self) -> KeyValue:
        if self.kv_store is None:
            self.kv_store = await self.jetstream.key_value(self.bucket_name)
        return self.kv_store

    async def get(self, key: str) -> MsgType | None:
        store = await self._get_store()
        try:
            entry = await store.get(key)
            if entry and entry.value:
                msg = self.msg_builder()
                msg.ParseFromString(entry.value)
                return msg  # type: ignore[no-any-return]
        except Exception:
            return None
        return None

    async def set(self, key: str, value: MsgType) -> None:
        store = await self._get_store()
        await store.put(key, value.SerializeToString())

    async def keys(self) -> list[str]:
        store = await self._get_store()
        return await store.keys()


class NatsSet:
    """
    A set-like data structure backed by a NATS Key-Value Store.
    """

    def __init__(self, jetstream: JetStreamContext, bucket_name: str):
        self.jetstream = jetstream
        self.bucket_name = bucket_name
        self.kv_store: KeyValue | None = None

    async def _get_store(self) -> KeyValue:
        if self.kv_store is None:
            self.kv_store = await self.jetstream.key_value(self.bucket_name)
        return self.kv_store

    async def add(self, member: str) -> None:
        store = await self._get_store()
        await store.put(member, b"1")

    async def members(self) -> list[str]:
        store = await self._get_store()
        return await store.keys()

    async def contains(self, member: str) -> bool:
        store = await self._get_store()
        try:
            entry = await store.get(member)
            return entry is not None
        except Exception:
            return False


class NatsHarnessWeights(NatsMap[WeightedHarness]):
    def __init__(self, jetstream: JetStreamContext):
        super().__init__(jetstream, "harness_weights", WeightedHarness)

    async def list_harnesses(self) -> list[WeightedHarness]:
        keys = await self.keys()
        harnesses = []
        for key in keys:
            harness = await self.get(key)
            if harness:
                harnesses.append(harness)
        return harnesses


class NatsCoverageMap(NatsMap[FunctionCoverage]):
    def __init__(self, jetstream: JetStreamContext, harness_name: str, package_name: str, task_id: str):
        bucket_name = f"coverage_{task_id}_{package_name}_{harness_name}"
        super().__init__(jetstream, bucket_name, FunctionCoverage)

    async def list_function_coverage(self) -> list[FunctionCoverage]:
        keys = await self.keys()
        coverages = []
        for key in keys:
            coverage = await self.get(key)
            if coverage:
                coverages.append(coverage)
        return coverages


class NatsBuildMap(NatsMap[BuildOutput]):
    def __init__(self, jetstream: JetStreamContext):
        super().__init__(jetstream, "builds", BuildOutput)

    def _build_key(self, task_id: str, build_type: BuildType) -> str:
        return f"{task_id}_{build_type}"

    async def get_builds(self, task_id: str, build_type: BuildType) -> list[BuildOutput]:
        key = self._build_key(task_id, build_type)
        build = await self.get(key)
        return [build] if build else []

    async def set_build(self, task_id: str, build_type: BuildType, build: BuildOutput) -> None:
        key = self._build_key(task_id, build_type)
        await self.set(key, build)


class NatsCrashSet(NatsSet):
    def __init__(self, jetstream: JetStreamContext):
        super().__init__(jetstream, "crash_set")


class NatsPoVReproduceStatus(NatsMap[POVReproduceResponse]):
    def __init__(self, jetstream: JetStreamContext):
        super().__init__(jetstream, "pov_reproduce_status", POVReproduceResponse)

    async def request_status(self, request: POVReproduceRequest) -> POVReproduceResponse | None:
        key = f"{request.task_id}_{request.internal_patch_id}_{request.harness_name}_{request.sanitizer}_{request.pov_path}"
        return await self.get(key)


class NatsMergedCorpusSetLock:
    def __init__(self, jetstream: JetStreamContext, task_id: str, harness_name: str, timeout: int):
        self.jetstream = jetstream
        self.lock_key = f"lock_{task_id}_{harness_name}"
        self.timeout = timeout
        self.kv_store: KeyValue | None = None

    async def _get_store(self) -> KeyValue:
        if self.kv_store is None:
            self.kv_store = await self.jetstream.key_value("merged_corpus_lock")
        return self.kv_store

    async def __aenter__(self) -> "NatsMergedCorpusSetLock":
        store = await self._get_store()
        try:
            await store.create(self.lock_key, b"1")
            return self
        except Exception:
            raise Exception("Failed to acquire lock")

    async def release(self) -> None:
        store = await self._get_store()
        await store.delete(self.lock_key)

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.release()


class NatsSARIFStore:
    def __init__(self, jetstream: JetStreamContext):
        self.jetstream = jetstream
        self.bucket_name = "sarif_store"
        self.kv_store: KeyValue | None = None

    async def _get_store(self) -> KeyValue:
        if self.kv_store is None:
            self.kv_store = await self.jetstream.key_value(self.bucket_name)
        return self.kv_store

    async def store(self, sarif_detail: SARIFBroadcastDetail) -> None:
        store = await self._get_store()
        key = sarif_detail.task_id
        try:
            entry = await store.get(key)
            if entry and entry.value:
                sarif_list = json.loads(entry.value)
            else:
                sarif_list = []
        except Exception:
            sarif_list = []

        sarif_list.append(sarif_detail.model_dump())
        await store.put(key, json.dumps(sarif_list).encode())

    async def get_by_task_id(self, task_id: str) -> List[SARIFBroadcastDetail]:
        store = await self._get_store()
        try:
            entry = await store.get(task_id)
            if entry and entry.value:
                sarif_list = json.loads(entry.value)
                return [SARIFBroadcastDetail.model_validate(item) for item in sarif_list]
        except Exception:
            return []
        return []


@dataclass
class NatsTaskRegistry:
    """Keep track of all tasks in the system"""

    jetstream: JetStreamContext
    tasks_kv: KeyValue | None = None
    cancelled_kv: KeyValue | None = None
    succeeded_kv: KeyValue | None = None
    errored_kv: KeyValue | None = None

    async def _get_tasks_store(self) -> KeyValue:
        if self.tasks_kv is None:
            self.tasks_kv = await self.jetstream.key_value("tasks_registry")
        return self.tasks_kv

    async def _get_cancelled_store(self) -> KeyValue:
        if self.cancelled_kv is None:
            self.cancelled_kv = await self.jetstream.key_value("cancelled_tasks")
        return self.cancelled_kv

    async def _get_succeeded_store(self) -> KeyValue:
        if self.succeeded_kv is None:
            self.succeeded_kv = await self.jetstream.key_value("succeeded_tasks")
        return self.succeeded_kv

    async def _get_errored_store(self) -> KeyValue:
        if self.errored_kv is None:
            self.errored_kv = await self.jetstream.key_value("errored_tasks")
        return self.errored_kv

    def _prepare_key(self, task_id: str) -> str:
        return task_id.lower()

    async def set(self, task: Task) -> None:
        """Update a task in the registry"""
        store = await self._get_tasks_store()
        await store.put(self._prepare_key(task.task_id), task.SerializeToString())

    async def get(self, task_id: str) -> Task | None:
        """Get a task from the registry"""
        store = await self._get_tasks_store()
        entry = await store.get(self._prepare_key(task_id))
        if entry and entry.value:
            task = Task()
            task.ParseFromString(entry.value)
            task.cancelled = await self.is_cancelled(task_id)
            return task
        return None

    async def delete(self, task_id: str) -> None:
        """Delete a task from the registry"""
        tasks_store = await self._get_tasks_store()
        await tasks_store.delete(self._prepare_key(task_id))
        cancelled_store = await self._get_cancelled_store()
        await cancelled_store.delete(self._prepare_key(task_id))

    async def mark_cancelled(self, task_or_id: str | Task) -> None:
        """Mark a task as cancelled"""
        task_id = task_or_id.task_id if isinstance(task_or_id, Task) else task_or_id
        store = await self._get_cancelled_store()
        await store.put(self._prepare_key(task_id), b"1")

    async def is_cancelled(self, task_or_id: str | Task) -> bool:
        """Check if a task is cancelled"""
        task_id = task_or_id.task_id if isinstance(task_or_id, Task) else task_or_id
        store = await self._get_cancelled_store()
        entry = await store.get(self._prepare_key(task_id))
        return entry is not None
