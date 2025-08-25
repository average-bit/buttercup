from buttercup.common import node_local
from buttercup.fuzzing_infra.runner import Runner, Conf, FuzzConfiguration
from dataclasses import dataclass
import os
from buttercup.common.datastructures.msg_pb2 import BuildType, WeightedHarness
from buttercup.common.datastructures.aliases import BuildType as BuildTypeHint
from buttercup.common.corpus import Corpus
from buttercup.common.nats_datastructures import NatsHarnessWeights, NatsBuildMap, NatsMergedCorpusSetLock
from buttercup.common.utils import serve_loop_async, setup_periodic_zombie_reaper
from buttercup.common.logger import setup_package_logger
from nats.js.client import JetStreamContext
from typing import List
from os import PathLike
import random
from buttercup.common.datastructures.msg_pb2 import BuildOutput
import logging
from buttercup.common.challenge_task import ChallengeTask
from buttercup.fuzzing_infra.settings import FuzzerBotSettings
from buttercup.common.constants import ADDRESS_SANITIZER
from buttercup.common.telemetry import init_telemetry
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from buttercup.common.telemetry import set_crs_attributes, CRSActionCategory
import datetime
import shutil
import nats
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class FinalCorpus:
    """
    Represents the corpus after the merge operation has been performed.
    """

    def __init__(self, corpus: Corpus, push_remotely: set[str], delete_locally: set[str]):
        self._corpus = corpus
        self._push_remotely = push_remotely
        self._delete_locally = delete_locally

    def push_remotely(self) -> int:
        n = 0
        if self._push_remotely:
            n = len(self._push_remotely)
            self._corpus.sync_specific_files_to_remote(self._push_remotely)
            self._push_remotely.clear()
        return n

    def delete_locally(self) -> int:
        n = 0
        for file in self._delete_locally:
            try:
                self._corpus.remove_local_file(file)
                n += 1
            except Exception as e:
                logger.error(f"Error removing file {file} from local corpus {self._corpus.path}: {e}")
        self._delete_locally.clear()
        return n


@dataclass
class PartitionedCorpus:
    """
    Represents the corpus split into local and remote parts.
    """

    corpus: Corpus
    local_dir: PathLike[str]
    remote_dir: PathLike[str]
    local_only_files: set[str]
    remote_files: set[str]
    max_local_files: int = 500

    def __post_init__(self) -> None:
        local_files_list = list(self.local_only_files)
        random.shuffle(local_files_list)

        new_local_only_files = set()

        for file in local_files_list:
            try:
                shutil.copy(os.path.join(self.corpus.path, file), os.path.join(self.local_dir, file))
                new_local_only_files.add(file)
                if len(new_local_only_files) >= self.max_local_files:
                    break
            except Exception as e:
                logger.error(f"Error copying file {file} to local directory: {e}. Will be ignored in merge.")

        self.local_only_files = new_local_only_files

        for file in self.remote_files:
            try:
                shutil.copy(os.path.join(self.corpus.path, file), os.path.join(self.remote_dir, file))
            except Exception as e:
                shutil.copy(os.path.join(self.corpus.remote_path, file), os.path.join(self.remote_dir, file))
                logger.debug(f"Error copying file {file} to remote directory: {e}. Copied from remote storage instead.")

    def to_final(self) -> FinalCorpus:
        self.corpus.hash_corpus(os.fspath(self.remote_dir))

        files_in_new_remote_dir = set(os.listdir(self.remote_dir))

        assert self.remote_files.issubset(files_in_new_remote_dir), "Some remote files were lost during merge"
        assert files_in_new_remote_dir.issubset(self.remote_files.union(self.local_only_files)), (
            "Unexpected files appeared in merge output"
        )

        push_remotely = self.local_only_files & files_in_new_remote_dir
        delete_locally = self.local_only_files - files_in_new_remote_dir

        return FinalCorpus(self.corpus, push_remotely, delete_locally)


@dataclass
class BaseCorpus:
    """
    Represents the initial corpus state, before any merge operations have been performed.
    """

    corpus: Corpus
    local_dir: PathLike[str]
    remote_dir: PathLike[str]
    max_local_files: int = 500

    def partition_corpus(self) -> PartitionedCorpus:
        self.corpus.sync_from_remote()

        local_files = set([os.path.basename(x) for x in self.corpus.list_local_corpus() if Corpus.has_hashed_name(x)])
        remote_files = set([os.path.basename(x) for x in self.corpus.list_remote_corpus() if Corpus.has_hashed_name(x)])

        local_only_files = local_files - remote_files

        return PartitionedCorpus(
            corpus=self.corpus,
            local_dir=self.local_dir,
            remote_dir=self.remote_dir,
            local_only_files=local_only_files,
            remote_files=remote_files,
            max_local_files=self.max_local_files,
        )


class MergerBot:
    def __init__(
        self,
        jetstream: JetStreamContext,
        timeout_seconds: int,
        python: str,
        crs_scratch_dir: str,
        max_local_files: int = 500,
    ):
        self.jetstream = jetstream
        self.runner = Runner(Conf(timeout_seconds))
        self.python = python
        self.crs_scratch_dir = crs_scratch_dir
        self.harness_weights = NatsHarnessWeights(jetstream)
        self.builds = NatsBuildMap(jetstream)
        self.max_local_files = max_local_files

    def required_builds(self) -> List[BuildTypeHint]:
        return [BuildType.FUZZER]

    def _run_merge_operation(
        self,
        task: WeightedHarness,
        build: BuildOutput,
        remote_dir: PathLike[str],
        local_dir: PathLike[str],
        local_only_files: set[str],
        remote_files: set[str],
        corp: Corpus,
    ) -> None:
        with node_local.scratch_dir() as td:
            tsk = ChallengeTask(read_only_task_dir=build.task_dir, python_path=self.python)
            with tsk.get_rw_copy(work_dir=td) as local_tsk:
                build_dir = local_tsk.get_build_dir()

                fuzz_conf = FuzzConfiguration(
                    os.fspath(local_dir),
                    str(build_dir / task.harness_name),
                    build.engine,
                    build.sanitizer,
                )

                logger.info(f"Starting fuzzer merge for {build.engine} | {build.sanitizer} | {task.harness_name}")

                tracer = trace.get_tracer(__name__)
                with tracer.start_as_current_span("merge_corpus") as span:
                    set_crs_attributes(
                        span,
                        crs_action_category=CRSActionCategory.DYNAMIC_ANALYSIS,
                        crs_action_name="merge_corpus",
                        task_metadata=dict(tsk.task_meta.metadata),
                        extra_attributes={
                            "crs.action.target.harness": task.harness_name,
                            "crs.action.target.sanitizer": build.sanitizer,
                            "crs.action.target.engine": build.engine,
                            "fuzz.corpus.size": corp.local_corpus_size(),
                            "fuzz.corpus.update.method": "merge",
                            "fuzz.corpus.update.time": datetime.datetime.now().isoformat(),
                        },
                    )

                    self.runner.merge_corpus(fuzz_conf, os.fspath(remote_dir))
                    span.set_status(Status(StatusCode.OK))

    async def run_task(self, task: WeightedHarness, builds: list[BuildOutput]) -> bool:
        logger.debug(f"Running merge pass for {task.harness_name} | {task.package_name} | {task.task_id}")

        build = next(iter([b for b in builds if b.sanitizer == ADDRESS_SANITIZER]), None)
        if build is None:
            build = random.choice(builds)

        corp = Corpus(self.crs_scratch_dir, task.task_id, task.harness_name)
        corp.hash_new_corpus()

        try:
            async with NatsMergedCorpusSetLock(self.jetstream, task.task_id, task.harness_name, 10):
                with node_local.scratch_dir() as remote_dir, node_local.scratch_dir() as local_dir:
                    base_corpus = BaseCorpus(corp, local_dir, remote_dir, self.max_local_files)
                    partitioned_corpus = base_corpus.partition_corpus()

                    if not partitioned_corpus.local_only_files:
                        logger.debug(
                            f"Skipping merge for {task.harness_name} | {task.package_name} | {task.task_id} because local corpus is up to date"
                        )
                        return False

                    logger.info(
                        f"Found {len(partitioned_corpus.local_only_files)} files only in local corpus for {task.harness_name}. Will run merge operation."
                    )

                    try:
                        self._run_merge_operation(
                            task,
                            build,
                            remote_dir,
                            local_dir,
                            partitioned_corpus.local_only_files,
                            partitioned_corpus.remote_files,
                            corp,
                        )
                    except Exception as e:
                        logger.error(f"Error during merge operation: {e}")
                        raise e

                    final_corpus = partitioned_corpus.to_final()
                    push_count = final_corpus.push_remotely()
                    if push_count > 0:
                        logger.info(f"Synced {push_count} files that add coverage to remote corpus")

                    remove_count = final_corpus.delete_locally()
                    if remove_count > 0:
                        logger.info(
                            f"Removed {remove_count} files from local corpus {corp.path} that don't add coverage"
                        )
                    return True
        except Exception as e:
            logger.error(f"Error merging corpus: {e}")
            raise e

        return False

    async def serve_item(self) -> bool:
        weighted_items: list[WeightedHarness] = [
            wh for wh in await self.harness_weights.list_harnesses() if wh.weight > 0
        ]
        if len(weighted_items) <= 0:
            return False

        did_work = False
        n_exceptions = 0
        random.shuffle(weighted_items)
        for item in weighted_items:
            builds = await self.builds.get_builds(item.task_id, BuildType.FUZZER)
            if len(builds) <= 0:
                continue

            try:
                if await self.run_task(item, builds):
                    did_work = True
            except Exception as e:
                n_exceptions += 1
                logger.error(f"Error running task: {e}")
                if n_exceptions > 1:
                    logger.warning("Multiple exceptions occurred while running tasks, restarting")
                    raise e

        return did_work

    async def run(self) -> None:
        await serve_loop_async(self.serve_item, 10.0)


def main() -> None:
    args = FuzzerBotSettings()

    setup_package_logger("corpus-merger", __name__, args.log_level, args.log_max_line_length)
    init_telemetry("merger-bot")

    setup_periodic_zombie_reaper()

    logger.info(f"Starting merger (crs_scratch_dir: {args.crs_scratch_dir})")

    async def _main():
        nc = await nats.connect(args.nats_url)
        js = nc.jetstream()
        merger = MergerBot(js, args.timeout, args.python, args.crs_scratch_dir, args.max_local_files)
        await merger.run()
        await nc.close()

    asyncio.run(_main())


if __name__ == "__main__":
    main()
