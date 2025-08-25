from buttercup.common.nats_datastructures import NatsTaskRegistry
from google.protobuf import text_format
import nats
import asyncio
from pydantic_settings import BaseSettings
from typing import Annotated
from pydantic import Field


async def task_registry_cli() -> None:
    """CLI for the task registry"""

    class TaskRegistrySettings(BaseSettings):
        nats_url: Annotated[str, Field(default="nats://localhost:4222", description="NATS URL")]

        class Config:
            env_prefix = "BUTTERCUP_TASK_REGISTRY_"
            env_file = ".env"
            cli_parse_args = True
            extra = "allow"

    settings = TaskRegistrySettings()
    nc = await nats.connect(settings.nats_url)
    js = nc.jetstream()
    registry = NatsTaskRegistry(js)

    tasks_store = await registry._get_tasks_store()
    cancelled_store = await registry._get_cancelled_store()

    tasks = await tasks_store.keys()
    cancelled_tasks = await cancelled_store.keys()

    print(f"Number of tasks in registry: {len(tasks)}")
    print(f"Number of cancelled tasks: {len(cancelled_tasks)}")

    if len(cancelled_tasks) > 0:
        print("\nCancelled tasks:")
        for task_id in cancelled_tasks:
            print(f"- {task_id}")

    # Show task details
    for task_id in tasks:
        task = await registry.get(task_id)
        if task:
            print()
            print("-" * 80)
            print(f"Task ID: {task.task_id} {'(CANCELLED)' if task.cancelled else ''}")
            # Check if in cancelled set for verification
            is_in_set = await registry.is_cancelled(task.task_id)
            if is_in_set != task.cancelled:
                print(
                    f"WARNING: Inconsistency detected! In cancelled set: {is_in_set}, Task.cancelled: {task.cancelled}"
                )
            print(text_format.MessageToString(task, print_unknown_fields=True, indent=2))
            print("-" * 80)

    await nc.close()


if __name__ == "__main__":
    asyncio.run(task_registry_cli())
