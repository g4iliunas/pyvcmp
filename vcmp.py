from enum import Enum

VCMP_MAGIC = b"VCMP\x00"
VCMP_VERSION = 1


class VCMPPacket(Enum):
    HANDSHAKE = 1
    HANDSHAKE_ACK = 2
    PUBKEY = 3
    PUBKEY_ACK = 4
    READY = 5
