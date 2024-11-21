import asyncio
import websockets
from websockets.asyncio.server import ServerConnection
import logging
import json
import socks5

import struct

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from vcmp import *

rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

logger = logging.getLogger(__name__)

# mini helper functions


def parse_header(data: bytes) -> tuple[bytes, int, int]:
    magic = data[: len(VCMP_MAGIC)]
    version = data[len(VCMP_MAGIC)]
    type = data[len(VCMP_MAGIC) + 1]
    return magic, version, type


def is_handshake(header) -> bool:
    return header == (VCMP_MAGIC, VCMP_VERSION, VCMPPacket.HANDSHAKE.value)


def is_handshake_ack(header) -> bool:
    return header == (VCMP_MAGIC, VCMP_VERSION, VCMPPacket.HANDSHAKE_ACK.value)


def is_pubkey(header) -> bool:
    return header == (VCMP_MAGIC, VCMP_VERSION, VCMPPacket.PUBKEY.value)


def is_pubkey_ack(header) -> bool:
    return header == (VCMP_MAGIC, VCMP_VERSION, VCMPPacket.PUBKEY_ACK.value)


def is_ready(header) -> bool:
    return header == (VCMP_MAGIC, VCMP_VERSION, VCMPPacket.READY.value)


def is_data(header) -> bool:
    return header == (VCMP_MAGIC, VCMP_VERSION, VCMPPacket.DATA.value)


def extract_pubkey(data: bytes):
    args = data[len(VCMP_MAGIC) + 2 :]
    pubkey_len = struct.unpack(">i", args[:4])[0]
    pubkey_der = args[4:]
    return serialization.load_der_public_key(pubkey_der)


def extract_data(data: bytes) -> tuple[bytes, int]:
    args = data[len(VCMP_MAGIC) + 2 :]
    data_len = struct.unpack(">i", args[:4])[0]
    data = args[4:]
    return data, data_len


def decrypt_data(data: bytes):
    return rsa_private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_data(data: bytes, pubkey):
    return pubkey.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


class ListenerProtocol(asyncio.Protocol):
    def __init__(self, vcmp):
        self.vcmp: VCMP = vcmp
        self.transport = None
        self.state = 0

    def connection_made(self, transport):
        self.transport = transport

        peername = transport.get_extra_info("peername")
        logger.info(f"Connection from {peername}")

    def data_received(self, data):
        logger.debug(f"Data received: {data}")

        header = parse_header(data)

        match self.state:
            case 0:
                if is_handshake(header):
                    logger.info("Got handshake!")
                    self._send_handshake_ack()
                    self.state = 1
                else:
                    logger.debug("Not handshake")
                    self.transport.close()
            case 1:
                if is_pubkey(header):
                    logger.debug("Extracting pubkey")
                    pubkey = extract_pubkey(data)
                    self.vcmp.peers[self.transport] = {"pubkey": pubkey}
                    logger.debug("Sending our pubkey")
                    self._send_pubkey()
                    self.state = 2
                else:
                    logger.debug("Not pubkey")
                    self.transport.close()
            case 2:
                if is_ready(header):
                    logger.debug("Peer is ready to be communicated with!!")
                    self.state = 3

                    if self.vcmp.ws_client:
                        # todo: more detailed connect event
                        asyncio.gather(
                            self.vcmp.ws_client.send(
                                json.dumps({"event": "user_connect"})
                            )
                        )
                else:
                    logger.debug("Peer not ready")
                    self.transport.close()
            case 3:
                logger.debug("Received data from a ready peer")
                if is_data(header):
                    enc_data, length = extract_data(data)
                    dec = decrypt_data(enc_data)
                    logging.debug(f"Decrypted data: {dec.decode("utf-8")}")
                    if self.vcmp.ws_client:
                        asyncio.gather(
                            self.vcmp.ws_client.send(
                                json.dumps(
                                    {
                                        "event": "user_message",
                                        "data": dec.decode("utf-8"),
                                    }
                                )
                            )
                        )
                else:
                    logger.debug("Not data")
                    self.transport.close()

    def connection_lost(self, exc):
        if self.transport in self.vcmp.peers:
            del self.vcmp.peers[self.transport]

        if self.vcmp.ws_client:
            # todo: more detailed disconnect event
            asyncio.gather(
                self.vcmp.ws_client.send(json.dumps({"event": "user_disconnect"}))
            )

        logger.debug("Connection lost")

    def _send_handshake_ack(self):
        self.transport.write(
            VCMP_MAGIC
            + VCMP_VERSION.to_bytes()
            + VCMPPacket.HANDSHAKE_ACK.value.to_bytes()
        )

    def _send_pubkey(self):
        key = rsa_private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.transport.write(
            VCMP_MAGIC
            + VCMP_VERSION.to_bytes()
            + VCMPPacket.PUBKEY_ACK.value.to_bytes()
            + len(key).to_bytes(4)
            + key
        )


class PeerProtocol(asyncio.Protocol):
    def __init__(self, vcmp):
        self.vcmp: VCMP = vcmp
        self.transport = None
        self.state = 0

    def connection_made(self, transport):
        self.transport = transport

        peername = transport.get_extra_info("peername")
        logger.debug(f"Connection established with {peername}")

        self._send_handshake()

    def data_received(self, data):
        logger.debug(f"Data received: {data}")

        header = parse_header(data)

        match self.state:
            case 0:
                if is_handshake_ack(header):
                    logger.debug("Sending our pubkey")
                    self._send_pubkey()
                    self.state = 1
                else:
                    logger.debug("Not handshake ack")
                    self.transport.close()
            case 1:
                if is_pubkey_ack(header):
                    logger.debug("Extracting pubkey")
                    pubkey = extract_pubkey(data)
                    self.vcmp.peers[self.transport] = {"pubkey": pubkey}
                    logger.debug("Sending ready state")
                    self._send_ready()
                    self.state = 2

                    if self.vcmp.ws_client:
                        # todo: more detailed connect event
                        asyncio.gather(
                            self.vcmp.ws_client.send(
                                json.dumps({"event": "user_connect"})
                            )
                        )
                else:
                    logger.debug("Not pubkey ack")
                    self.transport.close()
            case 2:
                logger.debug("Received data from a ready peer")
                if is_data(header):
                    enc_data, length = extract_data(data)
                    dec = decrypt_data(enc_data)
                    logging.debug(f"Decrypted data: {dec.decode("utf-8")}")
                    if self.vcmp.ws_client:
                        asyncio.gather(
                            self.vcmp.ws_client.send(
                                json.dumps(
                                    {
                                        "event": "user_message",
                                        "data": dec.decode("utf-8"),
                                    }
                                )
                            )
                        )
                else:
                    logger.debug("Not data")
                    self.transport.close()

    def connection_lost(self, exc):
        if self.transport in self.vcmp.peers:
            del self.vcmp.peers[self.transport]

        if self.vcmp.ws_client:
            # todo: more detailed disconnect event
            asyncio.gather(
                self.vcmp.ws_client.send(json.dumps({"event": "user_disconnect"}))
            )

        logger.debug(f"Lost connection. Exc: {exc}")

    def _send_handshake(self):
        self.transport.write(
            VCMP_MAGIC + VCMP_VERSION.to_bytes() + VCMPPacket.HANDSHAKE.value.to_bytes()
        )

    def _send_pubkey(self):
        key = rsa_private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.transport.write(
            VCMP_MAGIC
            + VCMP_VERSION.to_bytes()
            + VCMPPacket.PUBKEY.value.to_bytes()
            + len(key).to_bytes(4)
            + key
        )

    def _send_ready(self):
        self.transport.write(
            VCMP_MAGIC + VCMP_VERSION.to_bytes() + VCMPPacket.READY.value.to_bytes()
        )


class VCMP:
    def __init__(
        self,
        listener_addr: tuple[str, int],
        wsapi_addr: tuple[str, int],
        proxy_addr: tuple[str, int],
    ) -> None:
        self.listener_addr = listener_addr
        self.wsapi_addr = wsapi_addr
        self.proxy_addr = proxy_addr
        self.ws_client: ServerConnection = None
        self.peers = dict()

    async def ws_handler(self, websocket: ServerConnection):
        if self.ws_client:
            logger.debug("Accepted some other websocket, but we only allow one session")
            return

        self.ws_client = websocket

        # all messages received will be in json format
        async for message in websocket:
            try:
                j: dict = json.loads(message)
                event: str = j.get("event")
                logger.debug(f"Event: {event}")

                match event:
                    case "connect":
                        addr = (j.get("address"), j.get("port"))
                        if not addr[0] or not addr[1]:
                            logger.debug("Failed to connect: no address or port")
                            websocket.close()
                            return

                        try:
                            # socks5 request to requested address
                            await socks5.create_connection(
                                lambda: PeerProtocol(self),
                                addr[0],
                                addr[1],
                                self.proxy_addr,
                            )

                        except Exception as e:
                            logger.error("Failed to create a peer connection:", e)

                            if self.ws_client:
                                self.ws_client.send(json.dumps({"event": "disconnect"}))
                    case "send_message":
                        if not self.peers:
                            logger.debug("No peers are present")
                            websocket.close()
                            return

                        data = j.get("data")
                        if not data:
                            logger.debug("WS client didnt specify data field")
                            websocket.close()
                            return

                        logger.debug(f"Querying message send request: {data}")

                        # encrypt the message with peer's pubkey
                        # for now, we will just take self.peers[0]
                        transports = list(self.peers.keys())
                        peer_transport = transports[0]
                        peer = self.peers[peer_transport]
                        peer_pubkey = peer["pubkey"]

                        enc = encrypt_data(data.encode("utf-8"), peer_pubkey)

                        peer_transport.write(
                            VCMP_MAGIC
                            + VCMP_VERSION.to_bytes()
                            + VCMPPacket.DATA.value.to_bytes()
                            + len(enc).to_bytes(4)
                            + enc
                        )

                    case "disconnect":
                        if not self.peers:
                            logger.debug("No peers are present")
                            websocket.close()
                            return

                        transports = list(self.peers.keys())
                        peer_transport = transports[0]
                        peer = self.peers[peer_transport]
                        logger.debug("Closing peer connection")
                        peer_transport.close()

            except json.JSONDecodeError:
                logger.error("Failed to decode event json")
                websocket.close()

        self.ws_client = None

    async def run(self):
        loop = asyncio.get_running_loop()

        # initialize both listener and ws servers
        listener = await loop.create_server(
            lambda: ListenerProtocol(self), self.listener_addr[0], self.listener_addr[1]
        )

        ws = await websockets.serve(
            self.ws_handler, self.wsapi_addr[0], self.wsapi_addr[1]
        )

        # gather the tasks and run them both concurrently
        await asyncio.gather(listener.serve_forever(), ws.serve_forever())
