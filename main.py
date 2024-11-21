from server import VCMP
import asyncio
import uvloop

import logging
import sys

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.DEBUG)
    logger.info("=== VCMP ===")

    vcmp = VCMP(("127.0.0.1", 55555), ("127.0.0.1", 44444), ("127.0.0.1", 9050))

    if sys.version_info >= (3, 11):
        with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
            runner.run(vcmp.run())
    else:
        uvloop.install()
        asyncio.run(vcmp.run())


if __name__ == "__main__":
    main()
