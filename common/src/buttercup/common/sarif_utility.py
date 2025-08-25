"""
Utility script for SARIF storage and retrieval operations.
"""

import argparse
import json
import nats
import asyncio
from nats.js.client import JetStreamContext

from buttercup.common.nats_datastructures import NatsSARIFStore


async def list_task_sarifs(jetstream: JetStreamContext, task_id: str, verbose: bool = False) -> None:
    """
    List all SARIF objects for a specific task.

    Args:
        jetstream: JetStreamContext
        task_id: Task ID
        verbose: Whether to print the full SARIF object
    """
    sarif_store = NatsSARIFStore(jetstream)

    sarifs = await sarif_store.get_by_task_id(task_id)
    print(f"Found {len(sarifs)} SARIF objects for task {task_id}")

    for sarif in sarifs:
        print(f"SARIF ID: {sarif.sarif_id}")
        if verbose:
            print(f"Metadata: {json.dumps(sarif.metadata, indent=2)}")
            print(f"SARIF content: {json.dumps(sarif.sarif, indent=2)}")
            print("-" * 80)


def main() -> None:
    """Main entry point for the utility script."""
    parser = argparse.ArgumentParser(description="SARIF storage and retrieval utility")
    parser.add_argument("--nats-url", default="nats://localhost:4222", help="NATS URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print the full SARIF object details")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    task_parser = subparsers.add_parser("task", help="List SARIF objects for a task")
    task_parser.add_argument("task_id", help="Task ID")

    args = parser.parse_args()

    async def _main():
        nc = await nats.connect(args.nats_url)
        js = nc.jetstream()

        if args.command == "task":
            await list_task_sarifs(js, args.task_id, args.verbose)
        else:
            parser.print_help()

        await nc.close()

    asyncio.run(_main())


if __name__ == "__main__":
    main()
