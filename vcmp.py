from enum import Enum

VCMP_MAGIC = b"VCMP\x00"
VCMP_VERSION = 1


class VCMPPacket(Enum):
    HANDSHAKE = 1
    HANDSHAKE_ACK = 2
    PUBKEY_BEGIN = 3
    PUBKEY = 4
    PUBKEY_ACK = 5
    PUBKEY_END = 6
    DATA = 7


class VCMPOpcode(Enum):
    IDENTIFY_BEGIN = 1
    IDENTIFY = 2
    IDENTIFY_ACK = 3
    IDENTIFY_END = 4
    TEXT = 5
