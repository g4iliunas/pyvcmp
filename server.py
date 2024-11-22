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


def make_header(packet_type: VCMPPacket) -> bytes:
    return struct.pack(
        "!{}scc".format(len(VCMP_MAGIC)),
        VCMP_MAGIC,
        VCMP_VERSION.to_bytes(1),
        packet_type.value.to_bytes(1),
    )


def parse_header(data: bytes):
    fmt = "!{}scc".format(len(VCMP_MAGIC))
    magic, version, packet_type = struct.unpack(fmt, data[: struct.calcsize(fmt)])
    return magic, int.from_bytes(version), int.from_bytes(packet_type)


def validate_header(magic, version) -> bool:
    return magic == VCMP_MAGIC and version == VCMP_VERSION


def parse_data(data: bytes) -> bytes:
    return data[len(VCMP_MAGIC) + 2 :]


class Base(asyncio.Protocol):
    def __init__(self, vcmp):
        self.vcmp: VCMP = vcmp
        self.transport = None
        self.state = 0

    def _send_pubkey(self, ack=None):
        key = rsa_private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return self.transport.write(
            make_header(VCMPPacket.PUBKEY_ACK if ack else VCMPPacket.PUBKEY) + key
        )

    def _send(self, opcode: VCMPOpcode, data: bytes = None):
        return self.transport.write(
            make_header(VCMPPacket.DATA)
            + encrypt_data(
                (
                    struct.pack(
                        "!c{}s".format(len(data)),
                        opcode.value.to_bytes(1),
                        data,
                    )
                    if data
                    else struct.pack("!c", opcode.value.to_bytes(1))
                ),
                self.vcmp.peers[self.transport]["pubkey"],
            ),
        )

    def _send_identify(self, ack=None):
        d = json.dumps(
            {
                "username": self.vcmp.username,
                "hostname": self.vcmp.hostname,
            }
        )
        return self._send(
            VCMPOpcode.IDENTIFY_ACK if ack else VCMPOpcode.IDENTIFY, d.encode("utf-8")
        )

    def _ws_send_user_conn(self):
        peer = self.vcmp.peers[self.transport]
        return asyncio.gather(
            self.vcmp.ws_client.send(
                json.dumps(
                    {
                        "event": "user_connect",
                        "username": peer["username"],
                        "hostname": peer["hostname"],
                    }
                )
            )
        )

    def _ws_send_user_msg(self, message: str, channel_id: int, username: str):
        return asyncio.gather(
            self.vcmp.ws_client.send(
                json.dumps(
                    {
                        "event": "user_message",
                        "data": message,
                        "channel_id": channel_id,
                        "username": username,
                    }
                )
            )
        )

    def connection_lost(self, exc):
        if self.transport in self.vcmp.peers:
            del self.vcmp.peers[self.transport]

        if self.vcmp.ws_client:
            # todo: more detailed disconnect event
            asyncio.gather(
                self.vcmp.ws_client.send(json.dumps({"event": "user_disconnect"}))
            )

        logger.debug(f"Lost connection. Exc: {exc}")


class ListenerProtocol(Base):
    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        logger.info(f"Connection from {peername}")

    def data_received(self, data):
        logger.debug(f"Data received: {data}")

        magic, version, packet_type = parse_header(data)
        contents = parse_data(data)

        logger.debug(f"Magic: {magic}, version: {version}, packet_type: {packet_type}")

        if not validate_header(magic, version):
            logger.debug("Closing transport since it sent us invalid header")
            self.transport.close()

        match self.state:
            case 0:
                if packet_type == VCMPPacket.HANDSHAKE.value:
                    logger.debug("Received a handshake, sending back an ACK")
                    self.transport.write(make_header(VCMPPacket.HANDSHAKE_ACK))
                    self.state = 1
                else:
                    logger.debug("Not handshake")
                    self.transport.close()
            case 1:
                if packet_type == VCMPPacket.PUBKEY_BEGIN.value:
                    logger.debug("Sending pubkey")
                    self._send_pubkey(ack=False)
                    self.state = 2
                else:
                    logger.debug("Not pubkey initiation")
                    self.transport.close()
            case 2:
                if packet_type == VCMPPacket.PUBKEY_ACK.value:
                    logger.debug("Extracting received pubkey")
                    self.vcmp.peers[self.transport] = {
                        "pubkey": serialization.load_der_public_key(contents),
                        "object": super(),
                    }
                    logger.debug("Ending pubkey transaction")
                    self.transport.write(make_header(VCMPPacket.PUBKEY_END))
                    self.state = 3
                else:
                    logger.debug("Not pubkey ACK")
                    self.transport.close()
            case _:
                if packet_type == VCMPPacket.DATA.value:
                    dec = decrypt_data(contents)
                    opcode, dec_contents = dec[0], dec[1:]
                    logger.debug(
                        f"Decrypted opcode: {opcode}, contents: {dec_contents}"
                    )

                    match self.state:
                        case 3:
                            if opcode == VCMPOpcode.IDENTIFY_BEGIN.value:
                                logger.debug("Sending information")
                                self._send_identify(ack=False)
                                self.state = 4
                            else:
                                logger.debug("Not opcode IDENTIFY_BEGIN")
                                self.transport.close()
                        case 4:
                            if opcode == VCMPOpcode.IDENTIFY_ACK.value:
                                d = json.loads(dec_contents)
                                logger.debug(f"Loaded identification json: {d}")

                                peer = self.vcmp.peers[self.transport]
                                peer["username"] = d["username"]
                                peer["hostname"] = d["hostname"]

                                logger.debug(
                                    f"Identification username: {d["username"]}, hostname: {d["hostname"]}"
                                )
                                logger.debug("Ending identification transaction")
                                self._send(VCMPOpcode.IDENTIFY_END)
                                self.state = 5

                                if self.vcmp.ws_client:
                                    self._ws_send_user_conn()
                            else:
                                logger.debug("Not opcode IDENTIFY_END")
                                self.transport.close()
                        case _:
                            if opcode == VCMPOpcode.TEXT.value:
                                d = json.loads(dec_contents)
                                logger.debug(f"Loaded text json: {d}")

                                # if self.vcmp.ws_client:
                                #    self._ws_send_user_msg(d["data"], d["channel_id"], self.vcmp.peers[self.transport]["username"])
                else:
                    logger.debug("Not data")
                    self.transport.close()


class PeerProtocol(Base):
    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        logger.debug(f"Connection established with {peername}")
        self.transport.write(make_header(VCMPPacket.HANDSHAKE))

    def data_received(self, data):
        logger.debug(f"Data received: {data}")

        magic, version, packet_type = parse_header(data)
        contents = parse_data(data)

        logger.debug(f"Magic: {magic}, version: {version}, packet_type: {packet_type}")

        if not validate_header(magic, version):
            logger.debug("Closing transport since it sent us invalid header")
            self.transport.close()

        match self.state:
            case 0:
                if packet_type == VCMPPacket.HANDSHAKE_ACK.value:
                    logger.debug(
                        "Received a handshake ACK, initiating a pubkey transaction"
                    )
                    self.transport.write(make_header(VCMPPacket.PUBKEY_BEGIN))
                    self.state = 1
                else:
                    logger.debug("Not handshake ACK")
                    self.transport.close()
            case 1:
                if packet_type == VCMPPacket.PUBKEY.value:
                    logger.debug("Extracting received pubkey")
                    self.vcmp.peers[self.transport] = {
                        "pubkey": serialization.load_der_public_key(contents),
                        "object": super(),
                    }
                    logger.debug("Sending pubkey ACK")
                    self._send_pubkey(ack=True)
                    self.state = 2
                else:
                    logger.debug("Not pubkey")
                    self.transport.close()
            case 2:
                if packet_type == VCMPPacket.PUBKEY_END.value:
                    logger.debug("Ended pubkey transaction")
                    logger.debug("Initiating an identification transaction")
                    self._send(VCMPOpcode.IDENTIFY_BEGIN)
                    self.state = 3
                else:
                    logger.debug("Not pubkey end")
                    self.transport.close()
            case _:
                if packet_type == VCMPPacket.DATA.value:
                    dec = decrypt_data(contents)
                    opcode, dec_contents = dec[0], dec[1:]
                    logger.debug(
                        f"Decrypted opcode: {opcode}, contents: {dec_contents}"
                    )

                    match self.state:
                        case 3:
                            if opcode == VCMPOpcode.IDENTIFY.value:
                                # parse identification
                                d = json.loads(dec_contents)
                                logger.debug(f"Loaded identification json: {d}")

                                peer = self.vcmp.peers[self.transport]
                                peer["username"] = d["username"]
                                peer["hostname"] = d["hostname"]

                                logger.debug(
                                    f"Identification username: {d["username"]}, hostname: {d["hostname"]}"
                                )
                                logger.debug("Sending information")
                                self._send_identify(ack=True)
                                self.state = 4
                            else:
                                logger.debug("Not opcode IDENTIFY")
                                self.transport.close()
                        case 4:
                            if opcode == VCMPOpcode.IDENTIFY_END.value:
                                logger.debug("Ended identification transaction")
                                self.state = 5

                                if self.vcmp.ws_client:
                                    self._ws_send_user_conn()
                            else:
                                logger.debug("Not opcode IDENTIFY_END")
                                self.transport.close()
                        case _:
                            if opcode == VCMPOpcode.TEXT.value:
                                d = json.loads(dec_contents)
                                logger.debug(f"Loaded text json: {d}")

                                # if self.vcmp.ws_client:
                                #    self._ws_send_user_msg(dec_contents.decode("utf-8"))
                else:
                    logger.debug("Not data")
                    self.transport.close()


class VCMP:
    def __init__(
        self,
        listener_addr: tuple[str, int],
        wsapi_addr: tuple[str, int],
        proxy_addr: tuple[str, int],
        username: str,
        hostname: str,
    ) -> None:
        self.listener_addr = listener_addr
        self.wsapi_addr = wsapi_addr
        self.proxy_addr = proxy_addr
        self.username = username
        self.hostname = hostname

        self.ws_client: ServerConnection = None
        self.peers = dict()

    async def ws_handler(self, websocket: ServerConnection):
        if self.ws_client:
            logger.debug("Accepted some other websocket, but we only allow one session")
            return

        self.ws_client = websocket

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
                            await websocket.close()
                            return

                        try:
                            await socks5.create_connection(
                                lambda: PeerProtocol(self),
                                addr[0],
                                addr[1],
                                self.proxy_addr,
                            )

                        except Exception as e:
                            logger.error("Failed to create a peer connection:", e)
                            await self.ws_client.send(
                                json.dumps({"event": "disconnect"})
                            )
                    case "send_message":
                        if not self.peers:
                            logger.debug("No peers are present")
                            await websocket.close()
                            return

                        data = j.get("data")
                        if not data:
                            logger.debug("WS client didnt specify data field")
                            await websocket.close()
                            return

                        logger.debug(f"Querying message send request: {data}")

                        transports = list(self.peers.keys())
                        peer_transport = transports[0]
                        peer = self.peers[peer_transport]

                        base: Base = peer["object"]
                        base._send(
                            VCMPOpcode.TEXT, json.dumps({"data": data}).encode("utf-8")
                        )

                    case "invite":
                        pass

                    case "list":
                        data = {"event": "list_peers", "peers": []}
                        for _, peer in self.peers.items():
                            data["peers"].append(
                                {
                                    "username": peer["username"],
                                    "hostname": peer["hostname"],
                                }
                            )
                        await websocket.send(json.dumps(data))

                    case "disconnect":
                        if not self.peers:
                            logger.debug("No peers are present")
                            await websocket.close()
                            return

                        transports = list(self.peers.keys())
                        peer_transport = transports[0]
                        peer = self.peers[peer_transport]
                        logger.debug("Closing peer connection")
                        peer_transport.close()

            except json.JSONDecodeError:
                logger.error("Failed to decode event json")
                await websocket.close()

        self.ws_client = None

    async def run(self):
        loop = asyncio.get_running_loop()

        # init listener
        listener = await loop.create_server(
            lambda: ListenerProtocol(self), self.listener_addr[0], self.listener_addr[1]
        )

        # init websockets server
        ws = await websockets.serve(
            self.ws_handler, self.wsapi_addr[0], self.wsapi_addr[1]
        )

        # gather the tasks and run them both concurrently
        await asyncio.gather(listener.serve_forever(), ws.serve_forever())
