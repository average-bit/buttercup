import logging
import os
import random
import tempfile
from pathlib import Path

from nats.js.client import JetStreamContext

from buttercup.common.challenge_task import ChallengeTask
from buttercup.common.corpus import Corpus, CrashDir
from buttercup.common.datastructures.aliases import BuildType as BuildTypeHint
from buttercup.common.datastructures.msg_pb2 import BuildOutput, BuildType, WeightedHarness
from buttercup.common.default_task_loop import TaskLoop
from buttercup.common.nats_datastructures import NatsCrashSet, NatsSARIFStore
from buttercup.common.nats_queues import NatsQueueFactory, QueueNames
from buttercup.common.project_yaml import ProjectYaml
from buttercup.common.reproduce_multiple import ReproduceMultiple
from buttercup.program_model.codequery import CodeQueryPersistent
from buttercup.seed_gen.function_selector import FunctionSelector
from buttercup.seed_gen.seed_explore import SeedExploreTask
from buttercup.seed_gen.seed_init import SeedInitTask
from buttercup.seed_gen.task import TaskName
from buttercup.seed_gen.task_counter import TaskCounter
from buttercup.seed_gen.vuln_base_task import CrashSubmit, VulnBaseTask
from buttercup.seed_gen.vuln_discovery_delta import VulnDiscoveryDeltaTask
from buttercup.seed_gen.vuln_discovery_full import VulnDiscoveryFullTask

logger = logging.getLogger(__name__)


class SeedGenBot(TaskLoop):
    TASK_SEED_INIT_PROB_FULL = 0.05
    TASK_VULN_DISCOVERY_PROB_FULL = 0.35
    TASK_SEED_EXPLORE_PROB_FULL = 0.60

    TASK_SEED_INIT_PROB_DELTA = 0.05
    TASK_VULN_DISCOVERY_PROB_DELTA = 0.45
    TASK_SEED_EXPLORE_PROB_DELTA = 0.50

    MIN_SEED_INIT_RUNS = 3
    MIN_VULN_DISCOVERY_RUNS = 1

    def __init__(
        self,
        jetstream: JetStreamContext,
        timer_seconds: int,
        wdir: Path,
        max_corpus_seed_size: int,
        max_pov_size: int,
        crash_dir_count_limit: int | None = None,
        corpus_root: str | None = None,
    ):
        self.wdir = wdir
        self.corpus_root = corpus_root
        self.jetstream = jetstream
        self.crash_set = NatsCrashSet(jetstream)
        self.crash_queue = NatsQueueFactory(jetstream.client, jetstream).create(QueueNames.CRASH)
        self.task_counter = TaskCounter(jetstream)
        self.crash_dir_count_limit = crash_dir_count_limit
        self.max_corpus_seed_size = max_corpus_seed_size
        self.max_pov_size = max_pov_size
        super().__init__(jetstream, timer_seconds)

    async def __post_init__(self):
        await self.crash_queue.__post_init__()

    def required_builds(self) -> list[BuildTypeHint]:
        return [BuildType.FUZZER]

    async def sample_task(self, task: WeightedHarness, is_delta: bool) -> str:
        seed_init_count = await self.task_counter.get_count(
            task.harness_name, task.package_name, task.task_id, TaskName.SEED_INIT.value
        )

        if seed_init_count < self.MIN_SEED_INIT_RUNS:
            logger.info(f"seed-init has only been run {seed_init_count} times, forcing task")
            return TaskName.SEED_INIT.value

        vuln_discovery_count = await self.task_counter.get_count(
            task.harness_name, task.package_name, task.task_id, TaskName.VULN_DISCOVERY.value
        )

        if vuln_discovery_count < self.MIN_VULN_DISCOVERY_RUNS:
            logger.info(
                f"vuln-discovery has only been run {vuln_discovery_count} times, forcing task"
            )
            return TaskName.VULN_DISCOVERY.value

        if is_delta:
            task_distribution = [
                (TaskName.SEED_INIT.value, self.TASK_SEED_INIT_PROB_DELTA),
                (TaskName.VULN_DISCOVERY.value, self.TASK_VULN_DISCOVERY_PROB_DELTA),
                (TaskName.SEED_EXPLORE.value, self.TASK_SEED_EXPLORE_PROB_DELTA),
            ]
        else:
            task_distribution = [
                (TaskName.SEED_INIT.value, self.TASK_SEED_INIT_PROB_FULL),
                (TaskName.VULN_DISCOVERY.value, self.TASK_VULN_DISCOVERY_PROB_FULL),
                (TaskName.SEED_EXPLORE.value, self.TASK_SEED_EXPLORE_PROB_FULL),
            ]

        tasks, weights = zip(*task_distribution)
        result = random.choices(tasks, weights=weights, k=1)
        return str(result[0]) if result else ""

    async def run_task(
        self, task: WeightedHarness, builds: dict[BuildTypeHint, list[BuildOutput]]
    ) -> None:
        build_dir = Path(builds[BuildType.FUZZER][0].task_dir)
        ro_challenge_task = ChallengeTask(read_only_task_dir=build_dir)
        project_yaml = ProjectYaml(ro_challenge_task, task.package_name)
        task_id = ro_challenge_task.task_meta.task_id

        with (
            tempfile.TemporaryDirectory(dir=self.wdir / task_id, prefix="seedgen-") as temp_dir_str,
            ro_challenge_task.get_rw_copy(work_dir=temp_dir_str) as challenge_task,
        ):
            logger.info(
                f"Running seed-gen for {task.harness_name} | {task.package_name} | {task.task_id}"
            )
            temp_dir = Path(temp_dir_str)
            logger.debug(f"Temp dir: {temp_dir}")
            out_dir = temp_dir / "seedgen-out"
            out_dir.mkdir()
            current_dir = temp_dir / "seedgen-current"
            current_dir.mkdir()

            logger.info("Initializing codequery")
            try:
                codequery = CodeQueryPersistent(challenge_task, work_dir=self.wdir)
            except Exception as e:
                logger.exception(f"Failed to initialize codequery: {e}.")
                return

            corp = Corpus(
                self.wdir.as_posix(),
                task.task_id,
                task.harness_name,
                copy_corpus_max_size=self.max_corpus_seed_size,
            )
            override_task = os.getenv("BUTTERCUP_SEED_GEN_TEST_TASK")
            if override_task:
                logger.info("Only testing task: %s", override_task)
            is_delta = challenge_task.is_delta_mode()
            task_choice = override_task if override_task else await self.sample_task(task, is_delta)

            logger.info(f"Running seed-gen task: {task_choice}")

            await self.task_counter.increment(
                task.harness_name, task.package_name, task.task_id, task_choice
            )

            if task_choice == TaskName.SEED_INIT.value:
                seed_init = SeedInitTask(
                    task.package_name,
                    task.harness_name,
                    challenge_task,
                    codequery,
                    project_yaml,
                    self.jetstream,
                )
                await seed_init.do_task(out_dir)
            elif task_choice == TaskName.VULN_DISCOVERY.value:
                sarif_store = NatsSARIFStore(self.jetstream)
                sarifs = await sarif_store.get_by_task_id(challenge_task.task_meta.task_id)
                fbuilds = builds[BuildType.FUZZER]
                reproduce_multiple = ReproduceMultiple(temp_dir, fbuilds)
                crash_submit = CrashSubmit(
                    crash_queue=self.crash_queue,
                    crash_set=self.crash_set,
                    crash_dir=CrashDir(
                        self.wdir.as_posix(),
                        task.task_id,
                        task.harness_name,
                        count_limit=self.crash_dir_count_limit,
                    ),
                    max_pov_size=self.max_pov_size,
                )
                with reproduce_multiple.open() as mult:
                    if is_delta:
                        vuln_discovery: VulnBaseTask = VulnDiscoveryDeltaTask(
                            task.package_name,
                            task.harness_name,
                            challenge_task,
                            codequery,
                            project_yaml,
                            self.jetstream,
                            mult,
                            sarifs,
                            crash_submit=crash_submit,
                        )
                    else:
                        vuln_discovery = VulnDiscoveryFullTask(
                            task.package_name,
                            task.harness_name,
                            challenge_task,
                            codequery,
                            project_yaml,
                            self.jetstream,
                            mult,
                            sarifs,
                            crash_submit=crash_submit,
                        )
                    await vuln_discovery.do_task(out_dir, current_dir)
            elif task_choice == TaskName.SEED_EXPLORE.value:
                seed_explore = SeedExploreTask(
                    task.package_name,
                    task.harness_name,
                    challenge_task,
                    codequery,
                    project_yaml,
                    self.jetstream,
                )

                function_selector = FunctionSelector(self.jetstream)
                selected_function = await function_selector.sample_function(task)

                if selected_function is None:
                    logger.error("No function selected from coverage data, canceling seed-explore")
                    return

                function_name = selected_function.function_name
                function_paths = [Path(path_str) for path_str in selected_function.function_paths]

                await seed_explore.do_task(function_name, function_paths, out_dir)
            else:
                raise ValueError(f"Unexpected task: {task_choice}")

            copied_files = corp.copy_corpus(out_dir)
            logger.info("Copied %d files to corpus %s", len(copied_files), corp.corpus_dir)
            logger.info(
                f"Seed-gen finished for {task.harness_name} | {task.package_name} | {task.task_id}"
            )
