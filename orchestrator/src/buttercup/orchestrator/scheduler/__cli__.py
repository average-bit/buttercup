from buttercup.orchestrator.scheduler.config import (
    Settings,
    ServeCommand,
    ProcessBuildOutputCommand,
    ProcessReadyTaskCommand,
)
from buttercup.orchestrator.scheduler.scheduler import Scheduler
from buttercup.common.datastructures.msg_pb2 import Task, BuildOutput
from buttercup.common.logger import setup_package_logger
from buttercup.common.telemetry import init_telemetry

from pydantic_settings import get_subcommand
import logging
import nats
import asyncio

logger = logging.getLogger(__name__)


def _prepare_ready_task(command: ProcessReadyTaskCommand) -> Task:
    return Task(
        task_id=command.task_id,
        task_type=command.task_type,
        task_status=command.task_status,
    )


def _prepare_build_output(command: ProcessBuildOutputCommand) -> BuildOutput:
    return BuildOutput(
        engine=command.engine,
        sanitizer=command.sanitizer,
        output_ossfuzz_path=command.output_ossfuzz_path,
        source_path=command.source_path,
    )


async def main() -> None:
    settings = Settings()
    setup_package_logger("scheduler", __name__, settings.log_level, settings.log_max_line_length)
    logger.debug(f"Settings: {settings}")
    command = get_subcommand(settings)
    if isinstance(command, ServeCommand):
        init_telemetry("scheduler")
        nc = await nats.connect(command.nats_url)
        js = nc.jetstream()
        scheduler = Scheduler(
            settings.tasks_storage_dir,
            settings.scratch_dir,
            js,
            sleep_time=command.sleep_time,
            competition_api_url=command.competition_api_url,
            competition_api_key_id=command.competition_api_key_id,
            competition_api_key_token=command.competition_api_key_token,
            competition_api_cycle_time=command.competition_api_cycle_time,
            patch_submission_retry_limit=command.patch_submission_retry_limit,
            patch_requests_per_vulnerability=command.patch_requests_per_vulnerability,
        )
        await scheduler.__post_init__()
        await scheduler.serve()
        await nc.close()
    elif isinstance(command, ProcessReadyTaskCommand):
        scheduler = Scheduler(settings.tasks_storage_dir, settings.scratch_dir)
        task = _prepare_ready_task(command)
        build_request = scheduler.process_ready_task(task)
        print(build_request)
    elif isinstance(command, ProcessBuildOutputCommand):
        scheduler = Scheduler(settings.tasks_storage_dir, settings.scratch_dir)
        build_output = _prepare_build_output(command)
        targets = scheduler.process_build_output(build_output)
        print(targets)


if __name__ == "__main__":
    asyncio.run(main())
