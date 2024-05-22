from dataclasses import dataclass
from enum import Enum
import struct
from typing import Tuple, Any


class NameServicePackt:
    pass


class Opcode(Enum):
    QUERY = 0b0000
    REGISTRATION = 0b0101
    RELEASE = 0b0110
    WACK = 0b01100
    REFRESH = 0b1000


@dataclass
class NMFlags:
    AA: bool  # Authoritative Answer
    TC: bool  # Truncation
    RD: bool  # Recursion Desired
    RA: bool  # Recursion Available
    B: bool  # Broadcast Flag


class RCode(Enum):
    NO_ERR = 0x0  # No Error
    FMT_ERR = 0x1  # Format Error
    SRV_ERR = 0x2  # Server Failure
    IMP_ERR = 0x4  # Unsupport Request Error
    RFS_ERR = 0x5  # Refuse Error
    ACT_ERR = 0x6  # Active Error
    CFT_ERR = 0x7  # Name in Conflict Error


@dataclass
class NameServicePacketHeader:
    """
                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          QDCOUNT              |           ANCOUNT             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          NSCOUNT              |           ARCOUNT             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    name_trn_id: int  # Transaction ID
    r: bool  # RESPONSE Flag
    opcode: Opcode  # Packet type code
    nm_flags: NMFlags  # Flags for operation
    rcode: RCode  # Result code of request
    qdcount: int  # Number of entries in the question section
    adcount: int  # Number of resource records in answer section
    nscount: int  # Number of resource records in authority section
    arcount: int  # Number of resource records in additional records section

    def pack(self) -> bytes:
        self.__validate()
        name_trn_id_bytes: bytes = struct.pack("!H", self.name_trn_id)
        section_counts_bytes: bytes = struct.pack(
            "!HHHH", self.qdcount, self.adcount, self.nscount, self.arcount
        )
        return name_trn_id_bytes + self.__pack_second_dword() + section_counts_bytes

    @classmethod
    def unpack(cls, data: bytes) -> "NameServicePacketHeader":
        name_trn_id: int = struct.unpack("!H", data[0:2])[0]
        r, opcode, nm_flags, rcode = cls.__unpack_second_dword(
            struct.unpack("<H", data[2:4])[0]
        )
        remaining_data_dwords: Tuple[Any] = struct.unpack("!HHHH", data[4:])
        qscount: int = remaining_data_dwords[0]
        adcount: int = remaining_data_dwords[1]
        nscount: int = remaining_data_dwords[2]
        arcount: int = remaining_data_dwords[3]
        return cls(
            name_trn_id, r, opcode, nm_flags, rcode, qscount, adcount, nscount, arcount
        )

    def __validate(self) -> None:
        if not (0 <= self.name_trn_id < 65536):
            raise ValueError("NAME_TR_ID must be a valid uint16")
        if not (0 <= self.qdcount < 65536):
            raise ValueError("QDCOUNT must be a valid uint16")
        if not (0 <= self.adcount < 65536):
            raise ValueError("ADCOUNT must be a valid uint16")
        if not (0 <= self.nscount < 65536):
            raise ValueError("NSCOUNT must be a valid uint16")
        if not (0 <= self.arcount < 65536):
            raise ValueError("ARCOUNT must be a valid uint16")
        return

    def __pack_second_dword(self) -> bytes:
        metadata_dword: int = 1 if self.r else 0
        metadata_dword |= self.opcode.value << 1
        metadata_dword |= 1 << 5 if self.nm_flags.AA else 0
        metadata_dword |= 1 << 6 if self.nm_flags.TC else 0
        metadata_dword |= 1 << 7 if self.nm_flags.RD else 0
        metadata_dword |= 1 << 8 if self.nm_flags.RA else 0
        metadata_dword |= 1 << 11 if self.nm_flags.B else 0
        metadata_dword |= self.rcode.value << 12
        return struct.pack("<H", metadata_dword)

    @staticmethod
    def __unpack_second_dword(data: int) -> Tuple[bool, Opcode, NMFlags, RCode]:
        print(bin(data))
        r = bool(0b1 & data)
        opcode = Opcode((data >> 1) & 0b1111)
        nm_flags = NMFlags(
            AA=bool(data & 0b100000),
            TC=bool(data & 0b1000000),
            RD=bool(data & 0b10000000),
            RA=bool(data & 0b100000000),
            B=bool(data & 0b100000000000),
        )
        rcode = RCode(data >> 12)
        return (r, opcode, nm_flags, rcode)


class NameServivceQuestionEntry:
    pass


class NameServivceAnswerResourceRecord:
    def __init__(self):
        pass


class NameServivceAuthorityResourceRecord:
    def __init__(self):
        pass


class NameServivceAdditionalResourceRecord:
    def __init__(self):
        pass
