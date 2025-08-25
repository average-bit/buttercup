import logging
from buttercup.program_model.program_model import ProgramModel
from buttercup.program_model.settings import (
    Settings,
    ServeCommand,
    ProcessCommand,
)
from buttercup.common.logger import setup_package_logger
from buttercup.common.telemetry import init_telemetry
from pydantic_settings import get_subcommand
from buttercup.common.datastructures.msg_pb2 import IndexRequest
import nats
import asyncio

logger = logging.getLogger(__name__)


def prepare_task(command: ProcessCommand) -> IndexRequest:
    """Prepares task for indexing."""

    return IndexRequest(
        task_dir=command.task_dir,
        task_id=command.task_id,
    )


async def main() -> None:
    settings = Settings()
    command = get_subcommand(settings)
    setup_package_logger(
        "program-model", __name__, settings.log_level, settings.log_max_line_length
    )

    if isinstance(command, ServeCommand):
        init_telemetry("program-model")
        nc = await nats.connect(command.nats_url)
        js = nc.jetstream()
        program_model = ProgramModel(
            sleep_time=command.sleep_time,
            jetstream=js,
            wdir=settings.scratch_dir,
            python=command.python,
            allow_pull=command.allow_pull,
        )
        await program_model.__post_init__()
        await program_model.serve()
        await nc.close()
    elif isinstance(command, ProcessCommand):
        task = prepare_task(command)
        program_model = ProgramModel(
            wdir=settings.scratch_dir,
            python=command.python,
            allow_pull=command.allow_pull,
        )
        program_model.process_task(task)


if __name__ == "__main__":
    asyncio.run(main())
