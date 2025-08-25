import argparse
import nats
import asyncio
from buttercup.common.nats_queues import NatsQueueFactory, QueueNames
from buttercup.common.datastructures.msg_pb2 import BuildRequest, BuildType


async def main() -> None:
    prsr = argparse.ArgumentParser("stimulate build bot manually")
    prsr.add_argument("--target_package", required=True)
    prsr.add_argument("--ossfuzz", required=True)
    prsr.add_argument("--engine", required=True)
    prsr.add_argument("--nats_url", default="nats://127.0.0.1:4222")
    prsr.add_argument("--sanitizer", required=True)
    prsr.add_argument("--source_path", required=True)
    prsr.add_argument("--task_id", required=True)
    prsr.add_argument("--build_type", required=True)
    args = prsr.parse_args()

    nc = await nats.connect(args.nats_url)
    js = nc.jetstream()
    queue = NatsQueueFactory(nc, js).create(QueueNames.BUILD)
    await queue.__post_init__()

    req = BuildRequest(
        engine=args.engine,
        sanitizer=args.sanitizer,
        ossfuzz=args.ossfuzz,
        source_path=args.source_path,
        task_id=args.task_id,
        build_type=args.build_type,
    )

    coverage_req = BuildRequest(
        engine=args.engine,
        sanitizer="coverage",
        ossfuzz=args.ossfuzz,
        source_path=args.source_path,
        task_id=args.task_id,
        build_type=BuildType.COVERAGE,
    )

    await queue.push(req)
    await queue.push(coverage_req)
    await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
