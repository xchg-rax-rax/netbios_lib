from dataclasses import dataclass
from enum import Enum
import struct
from typing import Tuple, Any, List
from netbios_name import NetBIOSName

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

class QuestionType(Enum):
    NB = 0x0020  # NetBIOS general Name Service Resource Record
    NBSTAT = 0x0021  # NetBIOS NODE STATUS Resource Record

class QuestionClass(Enum):
    IN = 0x0001  # Internet Class

@dataclass
class NameServivceQuestionEntry:
    """
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                         QUESTION_NAME                         /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         QUESTION_TYPE         |        QUESTION_CLASS         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    question_name: NetBIOSName
    question_type: QuestionType
    question_class: QuestionClass

    def pack(self) -> bytes:
        question_name_bytes: bytes = self.question_name.encoded_netbios_name
        question_type_bytes: bytes = struct.pack('!H', self.question_type.value)
        question_class_bytes: bytes = struct.pack('!H', self.question_class.value)
        return question_name_bytes + question_type_bytes + question_class_bytes

    @classmethod
    def unpack(cls, data: bytes) -> 'NameServivceQuestionEntry':
        question_name_bytes = data[:-4]
        question_name = NetBIOSName(question_name_bytes)
        question_type_ordinal, = struct.unpack('!H', data[-4:-2])
        question_type = QuestionType(question_type_ordinal)
        question_class_ordinal, = struct.unpack('!H', data[-2:])
        question_class = QuestionClass(question_class_ordinal)
        return cls(question_name, question_type, question_class)

class ResourceRecordType(Enum):
    AA = 0x0001
    NS = 0x0002
    NULL = 0x000A
    NB = 0x0020
    NBSTAT = 0x0021


class ResourceRecordClass(Enum):
    IN = 0x0001

    
@dataclass
class NameServivceResourceRecord:
    """
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                            RR_NAME                            /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           RR_TYPE             |          RR_CLASS             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              TTL                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           RDLENGTH            |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   /                                                               /
   /                             RDATA                             /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    rr_name: NetBIOSName
    rr_type: ResourceRecordType
    rr_class: ResourceRecordClass
    ttl: int
    rd_length: int
    r_data: bytes # PROVISIONAL
    
    def pack(self) -> bytes:
        rr_name_bytes: bytes = self.rr_name.encoded_netbios_name
        rr_type_bytes: bytes = struct.pack("!H", self.rr_type.value)
        rr_class_bytes: bytes = struct.pack("!H", self.rr_class.value)
        ttl_bytes = struct.pack("!Q", self.rr_class.value)
        rd_length_bytes: bytes = struct.pack("!H", self.rd_length)
        return rr_name_bytes + rr_type_bytes + rr_class_bytes + ttl_bytes + rd_length_bytes + self.r_data

    @classmethod
    def unpack(cls, data: bytes) -> 'NameServivceResourceRecord':
        last_byte_of_rr_name_index: int = data.index(b'\x00')
        rr_name_bytes: bytes = data[:last_byte_of_rr_name_index + 1]
        rr_name = NetBIOSName(rr_name_bytes)
        rr_type_bytes: bytes = data[last_byte_of_rr_name_index:last_byte_of_rr_name_index+2]
        rr_type = ResourceRecordType(struct.unpack('!H', rr_type_bytes))
        rr_class_bytes: bytes = data[last_byte_of_rr_name_index+2:last_byte_of_rr_name_index+4]
        rr_class = ResourceRecordClass(struct.unpack('!H', rr_class_bytes))
        ttl_class_bytes: bytes = data[last_byte_of_rr_name_index+4:last_byte_of_rr_name_index+8]
        ttl: int = struct.unpack('!Q', ttl_class_bytes)[0]
        rd_length_bytes: bytes = data[last_byte_of_rr_name_index+8:last_byte_of_rr_name_index+10]
        rd_length: int = struct.unpack('!H', rd_length_bytes)[0]
        r_data: bytes = data[last_byte_of_rr_name_index+10:]
        return cls(rr_name, rr_type, rr_class, ttl, rd_length, r_data)

@dataclass
class NameServicePackt:
    header: NameServicePacketHeader
    question_entries: List[NameServivceQuestionEntry]
    answer_resource_records: List[NameServivceResourceRecord]
    authority_resource_records: List[NameServivceResourceRecord]
    additional_resource_records: List[NameServivceResourceRecord]

    def pack(self) -> bytes:
        assert False
        return b''

    @classmethod
    def unpack(cls, data: bytes) -> 'NameServicePackt':
        assert False
        return cls()
