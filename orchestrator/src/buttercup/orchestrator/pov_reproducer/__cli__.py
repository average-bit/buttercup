from buttercup.orchestrator.pov_reproducer.config import Settings
from buttercup.orchestrator.pov_reproducer.pov_reproducer import POVReproducer
from buttercup.common.logger import setup_package_logger
import logging
import nats
import asyncio

logger = logging.getLogger(__name__)


async def main() -> None:
    settings = Settings()
    setup_package_logger("pov-reproducer", __name__, settings.log_level)
    logger.info(f"Starting POV Reproducer with settings: {settings}")

    nc = await nats.connect(settings.nats_url)
    js = nc.jetstream()
    service = POVReproducer(js, settings.sleep_time, settings.max_retries)
    await service.__post_init__()
    await service.serve()
    await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
