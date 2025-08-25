import logging
import requests
import tarfile
from dataclasses import dataclass, field
import uuid
import tempfile
from pathlib import Path
from typing import Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from nats.js.client import JetStreamContext
from buttercup.common.nats_queues import NatsQueue, NatsQueueFactory, QueueNames, GroupNames
from buttercup.common.datastructures.msg_pb2 import Task, SourceDetail, TaskDownload, TaskReady
from buttercup.orchestrator.utils import response_stream_to_file
from buttercup.common.task_meta import TaskMeta
from buttercup.common.nats_datastructures import NatsTaskRegistry
from buttercup.common.utils import serve_loop_async
import buttercup.common.node_local as node_local

logger = logging.getLogger(__name__)


@dataclass
class Downloader:
    download_dir: Path
    sleep_time: float = 0.1
    jetstream: JetStreamContext | None = None
    task_queue: NatsQueue | None = field(init=False, default=None)
    ready_queue: NatsQueue | None = field(init=False, default=None)
    registry: NatsTaskRegistry | None = field(init=False, default=None)
    session: requests.Session = field(init=False)

    async def __post_init__(self) -> None:
        if self.jetstream is not None:
            logger.debug("Using NATS for task queue and registry")
            queue_factory = NatsQueueFactory(self.jetstream.client, self.jetstream)
            self.task_queue = queue_factory.create(QueueNames.DOWNLOAD_TASKS, GroupNames.ORCHESTRATOR)
            await self.task_queue.__post_init__()
            self.ready_queue = queue_factory.create(QueueNames.READY_TASKS)
            await self.ready_queue.__post_init__()
            self.registry = NatsTaskRegistry(self.jetstream)

        self.download_dir.mkdir(parents=True, exist_ok=True)

        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            pool_connections=100,
            pool_maxsize=100,
            max_retries=retry_strategy,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get_task_dir(self, task_id: str) -> Path:
        return self.download_dir / task_id

    def download_source(self, task_id: str, tmp_task_dir: Path, source: SourceDetail) -> Optional[Path]:
        try:
            filepath = tmp_task_dir / str(uuid.uuid4())
            logger.info(f"[task {task_id}] Downloading source type {source.source_type} to {filepath}")
            sha256_hash = response_stream_to_file(self.session, source.url, filepath)

            if sha256_hash != source.sha256:
                logger.error(f"[task {task_id}] SHA256 mismatch for {source.url}")
                return None

            logger.info(f"[task {task_id}] Successfully downloaded source type {source.source_type} to {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to download {source.url}: {str(e)}")
            return None

    def _get_source_type_dir(self, source_type: SourceDetail.SourceType) -> str:
        if source_type == SourceDetail.SourceType.SOURCE_TYPE_REPO:
            return "src"
        elif source_type == SourceDetail.SourceType.SOURCE_TYPE_FUZZ_TOOLING:
            return "fuzz-tooling"
        elif source_type == SourceDetail.SourceType.SOURCE_TYPE_DIFF:
            return "diff"
        else:
            raise ValueError(f"Unknown source type: {source_type}")

    def extract_source(self, task_id: str, tmp_task_dir: Path, source: SourceDetail, source_file: Path) -> bool:
        try:
            logger.info(f"[task {task_id}] Extracting {source.url}")
            destination = tmp_task_dir / self._get_source_type_dir(source.source_type)
            destination.mkdir(parents=True, exist_ok=True)

            def is_within_directory(directory: Path, target: Path) -> bool:
                try:
                    target.relative_to(directory)
                    return True
                except ValueError:
                    return False

            def safe_extract(tar: tarfile.TarFile, path: Path) -> None:
                for member in tar.getmembers():
                    member_path = path / member.name
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted path traversal in tar file")

            with tarfile.open(source_file) as tar:
                safe_extract(tar, destination)
                for member in tar.getmembers():
                    tar.extract(member, path=destination)

            logger.info(f"[task {task_id}] Successfully extracted {source_file}")
            return True
        except Exception as e:
            logger.error(f"[task {task_id}] Failed to extract {source_file}: {str(e)}")
            return False

    def _download_and_extract_sources(self, task_id: str, tmp_task_dir: Path, sources: list) -> bool:
        for source in sources:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                result = self.download_source(task_id, temp_path, source)
                if result is None:
                    return False
                if not self.extract_source(task_id, tmp_task_dir, source, result):
                    return False
        return True

    def process_task(self, task: Task) -> bool:
        logger.info(f"Processing task {task.task_id} (message_id={task.message_id})")
        download_path = self.get_task_dir(task.task_id)

        if download_path.exists():
            logger.warning(f"Remote path already exists: {download_path}. Skipping download.")
            return True

        logger.info(f"Storing task {task.task_id} at {download_path}")

        with node_local.scratch_dir() as temp_dir:
            if not self._do_download(temp_dir, task):
                return False

            renamed_dir = node_local.rename_atomically(temp_dir.path, download_path)
            if renamed_dir is not None:
                temp_dir.commit = True
                node_local.dir_to_remote_archive(download_path)
        return True

    def _do_download(self, tmp_task_dir: str | Path, task: Task) -> bool:
        tmp_task_dir_path = Path(tmp_task_dir)
        logger.info(f"[task {task.task_id}] Using temporary directory {tmp_task_dir}")

        success = self._download_and_extract_sources(task.task_id, tmp_task_dir_path, task.sources)
        if not success:
            logger.error(f"Failed to download and extract sources for task {task.task_id}")
            return False

        task_meta = TaskMeta(task.project_name, task.focus, task.task_id, dict(task.metadata))
        task_meta.save(tmp_task_dir_path)
        return True

    async def serve_item(self) -> bool:
        assert self.task_queue is not None
        assert self.ready_queue is not None
        assert self.registry is not None

        rq_item = await self.task_queue.pop()
        if rq_item is None:
            return False

        task_download: TaskDownload = rq_item.deserialized
        success = self.process_task(task_download.task)

        if success:
            await self.registry.set(task_download.task)
            await self.ready_queue.push(TaskReady(task=task_download.task))
            await self.task_queue.ack_item(rq_item)
            logger.info(f"Successfully processed task {task_download.task.task_id}")
        else:
            logger.error(f"Failed to process task {task_download.task.task_id}")

        return True

    async def serve(self) -> None:
        if self.task_queue is None or self.ready_queue is None:
            raise ValueError("Task queues are not initialized")

        logger.info("Starting downloader service")
        await serve_loop_async(self.serve_item, self.sleep_time)

    def cleanup(self) -> None:
        if self.session:
            self.session.close()

    def __enter__(self) -> "Downloader":
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: object | None
    ) -> None:
        self.cleanup()
