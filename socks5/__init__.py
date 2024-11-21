from .proto import SOCKS5Protocol
import asyncio


async def create_connection(
    protocol_factory, host: str, port: int, proxy: tuple[str, int]
) -> tuple:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_connection(
        lambda: SOCKS5Protocol(protocol_factory, (host, port)), proxy[0], proxy[1]
    )
    return transport, protocol
