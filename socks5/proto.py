import asyncio
import logging
import struct

logger = logging.getLogger(__name__)


class SOCKS5Protocol(asyncio.Protocol):
    def __init__(self, protocol_factory, dst: tuple[str, int]) -> None:
        self.protocol_factory = protocol_factory()
        self.dst = dst
        self.transport = None
        self.state = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        logger.debug("SOCKS5 connection made")
        self.transport = transport
        transport.write(b"\x05\x01\x00")  # no auth

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug(f"SOCKS5 connection lost: {exc}")
        self.protocol_factory.connection_lost(exc)

    def data_received(self, data: bytes) -> None:
        logger.debug(f"SOCKS5 data received: {data}")

        match self.state:
            case 0:
                if data == b"\x05\x00":
                    self._send_conn_request()
                    self.state = 1
                else:
                    logging.debug(
                        "Closing transport because the server refused no auth method"
                    )
                    self.transport.close()
            case 1:
                if data[0] == 0x05 and data[1] == 0x00:
                    logging.debug("SOCKS5 session now begins")
                    self.protocol_factory.connection_made(self.transport)
                    self.transport.set_protocol(self.protocol_factory)
                else:
                    logging.debug("SOCKS5 server failed to ack the request")
                    self.transport.close()

    def _send_conn_request(self) -> None:
        port_bytes = struct.pack(">H", self.dst[1])

        connect_request = (
            b"\x05\x01\x00\x03"
            + len(self.dst[0]).to_bytes(1)
            + self.dst[0].encode("ascii")
            + port_bytes
        )
        self.transport.write(connect_request)
        logger.debug(f"Sent SOCKS5 CONNECT request to {self.dst}")
