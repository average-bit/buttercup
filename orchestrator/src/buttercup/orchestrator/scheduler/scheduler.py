import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set, Union
from nats.js.client import JetStreamContext
from buttercup.common.nats_queues import NatsQueue, NatsQueueFactory, NQItem, QueueNames, GroupNames
from buttercup.common.nats_datastructures import NatsHarnessWeights, NatsBuildMap
from buttercup.common.challenge_task import ChallengeTask
from buttercup.common.datastructures.msg_pb2 import (
    TaskReady,
    Task,
    BuildRequest,
    BuildOutput,
    WeightedHarness,
    IndexRequest,
    BuildType,
    TracedCrash,
    Patch,
)
from buttercup.common.project_yaml import ProjectYaml
from buttercup.orchestrator.scheduler.cancellation import NatsCancellation
from buttercup.orchestrator.scheduler.submissions import NatsSubmissions as Submissions, CompetitionAPI
from buttercup.common.clusterfuzz_utils import get_fuzz_targets
from buttercup.orchestrator.api_client_factory import create_api_client
from buttercup.common.utils import serve_loop_async
from buttercup.common.nats_datastructures import NatsTaskRegistry
from buttercup.orchestrator.scheduler.status_checker import StatusChecker
import random
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class Scheduler:
    tasks_storage_dir: Path
    scratch_dir: Path
    jetstream: JetStreamContext | None = None
    sleep_time: float = 1.0
    competition_api_url: str = "http://competition-api:8080"
    competition_api_key_id: str = "api_key_id"
    competition_api_key_token: str = "api_key_token"
    competition_api_cycle_time: float = 10.0
    patch_submission_retry_limit: int = 60
    patch_requests_per_vulnerability: int = 1
    concurrent_patch_requests_per_task: int = 12

    ready_queue: NatsQueue | None = field(init=False, default=None)
    build_requests_queue: NatsQueue | None = field(init=False, default=None)
    build_output_queue: NatsQueue | None = field(init=False, default=None)
    index_queue: NatsQueue | None = field(init=False, default=None)
    index_output_queue: NatsQueue | None = field(init=False, default=None)
    harness_map: NatsHarnessWeights | None = field(init=False, default=None)
    build_map: NatsBuildMap | None = field(init=False, default=None)
    cancellation: NatsCancellation | None = field(init=False, default=None)
    task_registry: NatsTaskRegistry | None = field(init=False, default=None)
    cached_cancelled_ids: Set[str] = field(init=False, default_factory=set)
    status_checker: StatusChecker | None = field(init=False, default=None)
    patches_queue: NatsQueue | None = field(init=False, default=None)
    traced_vulnerabilities_queue: NatsQueue | None = field(init=False, default=None)
    submissions: Submissions = field(init=False)

    async def update_cached_cancelled_ids(self) -> bool:
        if self.task_registry is None:
            return False

        cancelled_ids = set(await self.task_registry.get_cancelled_task_ids())
        self.cached_cancelled_ids = cancelled_ids
        return len(self.cached_cancelled_ids) > 0

    async def should_stop_processing(self, task_or_id: Union[str, Task]) -> bool:
        if self.task_registry is None:
            return False
        return await self.task_registry.should_stop_processing(task_or_id, self.cached_cancelled_ids)

    async def __post_init__(self) -> None:
        if self.jetstream is not None:
            queue_factory = NatsQueueFactory(self.jetstream.client, self.jetstream)
            api_client = create_api_client(
                self.competition_api_url, self.competition_api_key_id, self.competition_api_key_token
            )
            self.cancellation = NatsCancellation(jetstream=self.jetstream)
            self.ready_queue = queue_factory.create(QueueNames.READY_TASKS, GroupNames.ORCHESTRATOR)
            await self.ready_queue.__post_init__()
            self.build_requests_queue = queue_factory.create(QueueNames.BUILD)
            await self.build_requests_queue.__post_init__()
            self.build_output_queue = queue_factory.create(QueueNames.BUILD_OUTPUT, GroupNames.ORCHESTRATOR)
            await self.build_output_queue.__post_init__()
            self.index_queue = queue_factory.create(QueueNames.INDEX)
            await self.index_queue.__post_init__()
            self.index_output_queue = queue_factory.create(QueueNames.INDEX_OUTPUT, GroupNames.ORCHESTRATOR)
            await self.index_output_queue.__post_init__()
            self.harness_map = NatsHarnessWeights(self.jetstream)
            self.build_map = NatsBuildMap(self.jetstream)
            self.task_registry = NatsTaskRegistry(self.jetstream)
            self.status_checker = StatusChecker(self.competition_api_cycle_time)
            self.submissions = Submissions(
                jetstream=self.jetstream,
                competition_api=CompetitionAPI(api_client, self.task_registry),
                task_registry=self.task_registry,
                tasks_storage_dir=self.tasks_storage_dir,
                patch_submission_retry_limit=self.patch_submission_retry_limit,
                patch_requests_per_vulnerability=self.patch_requests_per_vulnerability,
                concurrent_patch_requests_per_task=self.concurrent_patch_requests_per_task,
            )
            await self.submissions.__post_init__()
            self.patches_queue = queue_factory.create(QueueNames.PATCHES, GroupNames.ORCHESTRATOR)
            await self.patches_queue.__post_init__()
            self.traced_vulnerabilities_queue = queue_factory.create(
                QueueNames.TRACED_VULNERABILITIES, GroupNames.ORCHESTRATOR
            )
            await self.traced_vulnerabilities_queue.__post_init__()

    def select_preferred(self, available_options: list[str], preferred_order: list[str]) -> str:
        """Select from preferred options if available, otherwise random choice.

        Args:
            available_options: List of available options to choose from
            preferred_order: List of preferred options in priority order

        Returns:
            Selected option string
        """
        for preferred in preferred_order:
            if preferred in available_options:
                return preferred
        return random.choice(available_options)

    def process_ready_task(self, task: Task) -> list[BuildRequest]:
        """Parse a task that has been downloaded and is ready to be built"""
        logger.info(f"Processing ready task {task.task_id}")

        challenge_task = ChallengeTask(self.tasks_storage_dir / task.task_id)
        logger.info(f"Processing task {task.task_id} / {task.focus}")

        project_yaml = ProjectYaml(challenge_task, task.project_name)

        engine = self.select_preferred(project_yaml.fuzzing_engines, ["libfuzzer", "afl"])
        sanitizers = project_yaml.sanitizers
        logger.info(f"Selected engine={engine}, sanitizers={sanitizers} for task {task.task_id}")

        build_types = [
            (BuildType.COVERAGE, "coverage", True),
        ]

        for san in sanitizers:
            build_types.append((BuildType.FUZZER, san, True))
            if len(challenge_task.get_diffs()) > 0:
                build_types.append((BuildType.TRACER_NO_DIFF, san, False))

        build_requests = [
            BuildRequest(
                engine=engine,
                task_dir=str(challenge_task.task_dir),
                task_id=task.task_id,
                build_type=build_type,
                sanitizer=san,
                apply_diff=apply_diff,
            )
            for build_type, san, apply_diff in build_types
        ]

        return build_requests

    def process_build_output(self, build_output: BuildOutput) -> list[WeightedHarness]:
        """Process a build output"""
        logger.info(
            f"[{build_output.task_id}] Processing build output for type {BuildType.Name(build_output.build_type)} | {build_output.engine} | {build_output.sanitizer} | {build_output.task_dir} | {build_output.apply_diff}"
        )

        if build_output.build_type != BuildType.FUZZER:
            return []

        # TODO(Ian): what to do if a task dir doesnt need a python path?
        tsk = ChallengeTask(read_only_task_dir=build_output.task_dir, python_path="python")

        build_dir = tsk.get_build_dir()
        targets = get_fuzz_targets(build_dir)
        logger.debug(f"Found {len(targets)} targets: {targets}")

        return [
            WeightedHarness(
                weight=1.0,
                harness_name=Path(tgt).name,
                package_name=tsk.task_meta.project_name,
                task_id=build_output.task_id,
            )
            for tgt in targets
        ]

    async def serve_ready_task(self) -> bool:
        assert self.ready_queue is not None
        assert self.index_queue is not None
        assert self.build_requests_queue is not None
        task_ready_item: NQItem[TaskReady] | None = await self.ready_queue.pop()

        if task_ready_item is not None:
            task_ready: TaskReady = task_ready_item.deserialized

            if await self.should_stop_processing(task_ready.task):
                logger.info(
                    f"Skipping ready task processing for task {task_ready.task.task_id} as it is cancelled or expired"
                )
                await self.ready_queue.ack_item(task_ready_item)
                return True

            try:
                challenge_task = ChallengeTask(self.tasks_storage_dir / task_ready.task.task_id)
                index_request = IndexRequest(
                    task_id=task_ready.task.task_id,
                    task_dir=str(challenge_task.task_dir),
                    package_name=task_ready.task.project_name,
                )
                await self.index_queue.push(index_request)
                logger.info(f"Pushed index request for task {task_ready.task.task_id} to index queue")

                for build_req in self.process_ready_task(task_ready.task):
                    await self.build_requests_queue.push(build_req)
                    logger.info(
                        f"[{task_ready.task.task_id}] Pushed build request of type {BuildType.Name(build_req.build_type)} | {build_req.sanitizer} | {build_req.engine} | {build_req.apply_diff}"
                    )
                await self.ready_queue.ack_item(task_ready_item)
                return True
            except Exception as e:
                logger.exception(f"Failed to process task {task_ready.task.task_id}: {e}")
                return False

        return False

    async def _process_patched_build_output(self, build_output: BuildOutput) -> bool:
        logger.info(f"Processing patched build output for task {build_output.task_id}")
        if not await self.submissions.record_patched_build(build_output):
            logger.error(f"Failed to record patched build output for task {build_output.task_id}")
            return False
        return True

    async def _process_regular_build_output(self, build_output: BuildOutput) -> bool:
        assert self.harness_map is not None
        try:
            targets = self.process_build_output(build_output)
            for target in targets:
                await self.harness_map.set(f"{target.task_id}_{target.harness_name}", target)
            logger.info(
                f"Pushed {len(targets)} targets to fuzzer map for {build_output.task_id} | {build_output.engine} | {build_output.sanitizer} | {build_output.task_dir}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Failed to process build output for {build_output.task_id} | {build_output.engine} | {build_output.sanitizer} | {build_output.task_dir}: {e}"
            )
            return False

    async def serve_build_output(self) -> bool:
        assert self.build_output_queue is not None
        assert self.build_map is not None
        build_output_item = await self.build_output_queue.pop()
        if build_output_item is None:
            return False

        build_output = build_output_item.deserialized

        if await self.should_stop_processing(build_output.task_id):
            logger.info(
                f"Skipping build output processing for task {build_output.task_id} as it is cancelled or expired"
            )
            await self.build_output_queue.ack_item(build_output_item)
            return True

        await self.build_map.set_build(build_output.task_id, build_output.build_type, build_output)
        if build_output.build_type == BuildType.PATCH:
            res = await self._process_patched_build_output(build_output)
        else:
            res = await self._process_regular_build_output(build_output)

        if res:
            logger.info(
                f"Acked build output {build_output.task_id} | {build_output.engine} | {build_output.sanitizer} | {build_output.task_dir} | {build_output.internal_patch_id}"
            )
            await self.build_output_queue.ack_item(build_output_item)
            return True

        return False

    async def serve_index_output(self) -> bool:
        assert self.index_output_queue is not None
        index_output_item = await self.index_output_queue.pop()
        if index_output_item is not None:
            try:
                logger.info(f"Received index output for task {index_output_item.deserialized.task_id}")
                await self.index_output_queue.ack_item(index_output_item)
                return True
            except Exception as e:
                logger.error(f"Failed to process index output: {e}")
                return False
        return False

    async def update_expired_task_weights(self) -> bool:
        if not self.task_registry or not self.harness_map:
            return False

        harnesses = await self.harness_map.list_harnesses()
        any_updated = False

        for harness in harnesses:
            if harness.weight <= 0:
                continue

            if await self.should_stop_processing(harness.task_id):
                zero_weight_harness = WeightedHarness(
                    weight=-1.0,
                    harness_name=harness.harness_name,
                    package_name=harness.package_name,
                    task_id=harness.task_id,
                )
                await self.harness_map.set(f"{harness.task_id}_{harness.harness_name}", zero_weight_harness)
                logger.info(
                    f"Updated weight to -1.0 for cancelled/expired task {harness.task_id}, harness {harness.harness_name}"
                )
                any_updated = True

        return any_updated

    async def competition_api_interactions(self) -> bool:
        assert self.traced_vulnerabilities_queue is not None
        assert self.patches_queue is not None
        assert self.submissions is not None
        assert self.status_checker is not None
        collected_item = False
        vuln_item: NQItem[TracedCrash] | None = await self.traced_vulnerabilities_queue.pop()
        if vuln_item is not None:
            crash: TracedCrash = vuln_item.deserialized
            logger.info(f"Recording vulnerability for task {crash.crash.target.task_id}")
            if await self.submissions.submit_vulnerability(crash):
                await self.traced_vulnerabilities_queue.ack_item(vuln_item)
                collected_item = True

        patch_item: NQItem[Patch] | None = await self.patches_queue.pop()
        if patch_item is not None:
            patch: Patch = patch_item.deserialized
            logger.info(f"Appending patch for task {patch.task_id}")
            if await self.submissions.record_patch(patch):
                await self.patches_queue.ack_item(patch_item)
                collected_item = True

        async def do_check() -> bool:
            await self.submissions.process_cycle()
            return True

        await self.status_checker.check_statuses(do_check)

        return collected_item

    async def serve_item(self) -> bool:
        assert self.cancellation is not None
        results = await asyncio.gather(
            self.cancellation.process_cancellations(),
            self.update_cached_cancelled_ids(),
            self.serve_ready_task(),
            self.serve_build_output(),
            self.serve_index_output(),
            self.update_expired_task_weights(),
            self.competition_api_interactions(),
        )
        return any(results)

    async def serve(self) -> None:
        if self.jetstream is None:
            raise ValueError("JetStream is not initialized")

        logger.info("Starting scheduler service")
        await serve_loop_async(self.serve_item, self.sleep_time)
