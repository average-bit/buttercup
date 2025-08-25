from buttercup.common.logger import setup_package_logger
from buttercup.common.nats_datastructures import (
    NatsBuildMap,
    NatsHarnessWeights,
)
from buttercup.common.datastructures.msg_pb2 import (
    BuildOutput,
    BuildType,
    WeightedHarness,
    SubmissionEntry,
)
from buttercup.common.nats_queues import NatsQueueFactory, QueueNames, NatsQueue, GroupNames
from uuid import uuid4
import nats
from nats.js.client import JetStreamContext
from nats.aio.client import Client as NATS
from pydantic_settings import BaseSettings, CliSubCommand, CliPositionalArg, get_subcommand
from pydantic import BaseModel
from typing import Annotated
from pydantic import Field
from pathlib import Path
from google.protobuf.text_format import Parse
import logging
import asyncio

logger = logging.getLogger(__name__)

TaskId = str


class TaskResult(BaseModel):
    task_id: TaskId
    project_name: str
    mode: str
    n_vulnerabilities: int = 0
    n_patches: int = 0
    n_bundles: int = 0
    patched_vulnerabilities: list[str] = []
    non_patched_vulnerabilities: list[str] = []


def truncate_stacktraces(submission: SubmissionEntry, max_length: int = 80) -> SubmissionEntry:
    """Create a copy of the submission with truncated stacktraces for display purposes."""
    from google.protobuf import text_format

    submission_text = text_format.MessageToString(submission)
    truncated_submission = SubmissionEntry()
    text_format.Parse(submission_text, truncated_submission)

    for crash_with_id in truncated_submission.crashes:
        crash = crash_with_id.crash
        if crash.crash.stacktrace and len(crash.crash.stacktrace) > max_length:
            crash.crash.stacktrace = crash.crash.stacktrace[:max_length] + "... (truncated)"

        if crash.tracer_stacktrace and len(crash.tracer_stacktrace) > max_length:
            crash.tracer_stacktrace = crash.tracer_stacktrace[:max_length] + "... (truncated)"

        if crash.crash.crash_token and len(crash.crash.crash_token) > max_length:
            crash.crash.crash_token = crash.crash.crash_token[:max_length] + "... (truncated)"

    return truncated_submission


def get_queue_names() -> list[str]:
    return [f"'{queue_name.value}'" for queue_name in QueueNames]


def get_build_types() -> list[str]:
    return [f"'{build_type} ({BuildType.Name(build_type)})'" for build_type in BuildType.values()]


class SendSettings(BaseModel):
    queue_name: CliPositionalArg[str] = Field(description="Queue name (one of " + ", ".join(get_queue_names()) + ")")
    msg_path: CliPositionalArg[Path] = Field(description="Path to message file in Protobuf text format")


class ReadSettings(BaseModel):
    queue_name: CliPositionalArg[str] = Field(description="Queue name (one of " + ", ".join(get_queue_names()) + ")")
    group_name: Annotated[str | None, Field(description="Group name")] = None


class ListSettings(BaseModel):
    pass


class ReadHarnessWeightSettings(BaseModel):
    pass


class ReadBuildsSettings(BaseModel):
    task_id: CliPositionalArg[str] = Field(description="Task ID")
    build_type: CliPositionalArg[str] = Field(description="Build type (one of " + ", ".join(get_build_types()) + ")")


class ReadSubmissionsSettings(BaseModel):
    verbose: bool = Field(False, description="Show full stacktraces instead of truncated versions")
    filter_stop: bool = Field(False, description="Filter out submissions that are stopped")


class AddHarnessWeightSettings(BaseModel):
    msg_path: CliPositionalArg[Path] = Field(description="Path to WeightedHarness file in Protobuf text format")


class AddBuildSettings(BaseModel):
    msg_path: CliPositionalArg[Path] = Field(description="Path to BuildOutput file in Protobuf text format")


class DeleteSettings(BaseModel):
    queue_name: CliPositionalArg[str] = Field(description="Queue name (one of " + ", ".join(get_queue_names()) + ")")


class Settings(BaseSettings):
    nats_url: Annotated[str, Field(default="nats://localhost:4222", description="NATS URL")]
    log_level: Annotated[str, Field(default="info", description="Log level")]
    send_queue: CliSubCommand[SendSettings]
    read_queue: CliSubCommand[ReadSettings]
    list_queues: CliSubCommand[ListSettings]
    delete_queue: CliSubCommand[DeleteSettings]
    add_harness: CliSubCommand[AddHarnessWeightSettings]
    add_build: CliSubCommand[AddBuildSettings]
    read_harnesses: CliSubCommand[ReadHarnessWeightSettings]
    read_builds: CliSubCommand[ReadBuildsSettings]
    read_submissions: CliSubCommand[ReadSubmissionsSettings]

    class Config:
        env_prefix = "BUTTERCUP_MSG_PUBLISHER_"
        env_file = ".env"
        cli_parse_args = True
        nested_model_default_partial_update = True
        env_nested_delimiter = "__"
        extra = "allow"


async def handle_subcommand(nats_client: NATS, jetstream: JetStreamContext, command: BaseModel | None) -> None:
    if command is None:
        return

    if isinstance(command, SendSettings):
        try:
            queue_name = QueueNames(command.queue_name)
            queue: NatsQueue = NatsQueueFactory(nats_client, jetstream).create(queue_name)
        except Exception as e:
            logger.exception(f"Failed to create queue: {e}")
            return

        msg_builder = queue.msg_builder
        logger.info(f"Reading {msg_builder().__class__.__name__} message from file '{command.msg_path}'")
        msg = Parse(command.msg_path.read_text(), msg_builder())
        logger.info(f"Pushing message to queue '{command.queue_name}': {msg}")
        await queue.push(msg)
    elif isinstance(command, ReadSettings):
        queue_name = QueueNames(command.queue_name)
        group_name_str = "msg_publisher" + str(uuid4()) if command.group_name is None else command.group_name
        group_name = GroupNames(group_name_str)
        queue_with_group: NatsQueue = NatsQueueFactory(nats_client, jetstream).create(queue_name, group_name=group_name)
        await queue_with_group.init_consumer()

        while True:
            item = await queue_with_group.pop()
            if item is None:
                break

            print(item)
            print()

        logger.info("Done")
    elif isinstance(command, DeleteSettings):
        await jetstream.delete_stream(name=command.queue_name)
        logger.info(f"Deleted stream '{command.queue_name}'")
    elif isinstance(command, AddHarnessWeightSettings):
        msg = Parse(command.msg_path.read_text(), WeightedHarness())
        await NatsHarnessWeights(jetstream).set(f"{msg.task_id}_{msg.harness_name}", msg)
        logger.info(f"Added harness weight for {msg.package_name} | {msg.harness_name} | {msg.task_id}")
    elif isinstance(command, AddBuildSettings):
        msg = Parse(command.msg_path.read_text(), BuildOutput())
        await NatsBuildMap(jetstream).set_build(msg.task_id, msg.build_type, msg)
        logger.info(f"Added build for {msg.task_id} | {BuildType.Name(msg.build_type)} | {msg.sanitizer}")
    elif isinstance(command, ReadHarnessWeightSettings):
        for harness in await NatsHarnessWeights(jetstream).list_harnesses():
            print(harness)
        logger.info("Done")
    elif isinstance(command, ReadBuildsSettings):
        build_type = BuildType.Value(command.build_type)
        for build in await NatsBuildMap(jetstream).get_builds(command.task_id, build_type):
            print(build)
        logger.info("Done")
    elif isinstance(command, ReadSubmissionsSettings):
        # This command is not supported with NATS as it requires direct access to the underlying data store.
        # The user should use the nats CLI to inspect the contents of the submissions stream.
        logger.error("Reading submissions is not supported with NATS.")
        logger.info("Use the nats CLI to inspect the contents of the submissions stream.")
    elif isinstance(command, ListSettings):
        print("Available queues:")
        print("\n".join([f"- {name}" for name in get_queue_names()]))


async def main() -> None:
    settings = Settings()
    setup_package_logger("util-cli", __name__, settings.log_level)

    nc = await nats.connect(settings.nats_url)
    js = nc.jetstream()
    command = get_subcommand(settings)
    await handle_subcommand(nc, js, command)
    await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
