from server import VCMP
import asyncio
import uvloop

import logging
import sys
import json

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.DEBUG)
    logger.info("=== VCMP ===")

    with open("./config.json", "r") as f:
        config = json.load(f)

    servers = config["servers"]
    listener = servers["listener"]
    ws = servers["websocket"]
    tor_service = config["tor_service"]

    vcmp = VCMP(
        (listener["address"], listener["port"]),
        (ws["address"], ws["port"]),
        (tor_service["address"], tor_service["port"]),
        config["username"],
        config["hostname"],
    )

    if sys.version_info >= (3, 11):
        with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
            runner.run(vcmp.run())
    else:
        uvloop.install()
        asyncio.run(vcmp.run())


if __name__ == "__main__":
    main()
