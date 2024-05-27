from dataclasses import dataclass
from enum import Enum
import struct
from typing import Optional, Tuple, Any, List, Union
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
    ancount: int  # Number of resource records in answer section
    nscount: int  # Number of resource records in authority section
    arcount: int  # Number of resource records in additional records section

    def pack(self) -> bytes:
        self.__validate()
        name_trn_id_bytes: bytes = struct.pack("!H", self.name_trn_id)
        section_counts_bytes: bytes = struct.pack(
            "!HHHH", self.qdcount, self.ancount, self.nscount, self.arcount
        )
        return name_trn_id_bytes + self.__pack_second_dword() + section_counts_bytes

    @classmethod
    def unpack(cls, data: bytes) -> "NameServicePacketHeader":
        name_trn_id: int = struct.unpack("!H", data[0:2])[0]
        r, opcode, nm_flags, rcode = cls.__unpack_second_dword(
            struct.unpack("!H", data[2:4])[0]
        )
        remaining_data_dwords: Tuple[Any] = struct.unpack("!HHHH", data[4:])
        qscount: int = remaining_data_dwords[0]
        ancount: int = remaining_data_dwords[1]
        nscount: int = remaining_data_dwords[2]
        arcount: int = remaining_data_dwords[3]
        return cls(
            name_trn_id, r, opcode, nm_flags, rcode, qscount, ancount, nscount, arcount
        )

    def __validate(self) -> None:
        if not (0 <= self.name_trn_id < 65536):
            raise ValueError("NAME_TR_ID must be a valid uint16")
        if not (0 <= self.qdcount < 65536):
            raise ValueError("QDCOUNT must be a valid uint16")
        if not (0 <= self.ancount < 65536):
            raise ValueError("ADCOUNT must be a valid uint16")
        if not (0 <= self.nscount < 65536):
            raise ValueError("NSCOUNT must be a valid uint16")
        if not (0 <= self.arcount < 65536):
            raise ValueError("ARCOUNT must be a valid uint16")
        return

    def __pack_second_dword(self) -> bytes:
        # Broken AF
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
        r = bool(1 << 15 & data)
        opcode = Opcode((data >> 11) & 0b1111)
        nm_flags = NMFlags(
            AA=bool((data >> 10) & 0b1),
            TC=bool((data >> 9) & 0b1),
            RD=bool((data >> 8) & 0b1),
            RA=bool((data >> 7) & 0b1),
            B=bool((data >> 4) & 0b1),
        )
        rcode = RCode(data & 0b1111)
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
        question_type_bytes: bytes = struct.pack("!H", self.question_type.value)
        question_class_bytes: bytes = struct.pack("!H", self.question_class.value)
        return question_name_bytes + question_type_bytes + question_class_bytes

    @classmethod
    def unpack(cls, data: bytes) -> "NameServivceQuestionEntry":
        return cls.unpack_from_start_of_data(data)[0]

    @classmethod
    def unpack_from_start_of_data(
        cls, data: bytes
    ) -> Tuple["NameServivceQuestionEntry", int]:
        last_byte_of_question_name_index: int = data.index(b"\x00")
        question_name_bytes = data[:last_byte_of_question_name_index + 1]
        question_name = NetBIOSName(question_name_bytes)
        (question_type_ordinal,) = struct.unpack("!H", data[last_byte_of_question_name_index + 1:last_byte_of_question_name_index + 3])
        question_type = QuestionType(question_type_ordinal)
        (question_class_ordinal,) = struct.unpack("!H", data[last_byte_of_question_name_index + 3:last_byte_of_question_name_index + 5])
        question_class = QuestionClass(question_class_ordinal)
        return cls(question_name, question_type, question_class), len(question_name_bytes) +  4
        

class ResourceRecordType(Enum):
    AA = 0x0001
    NS = 0x0002
    NULL = 0x000A
    NB = 0x0020
    NBSTAT = 0x0021


class ResourceRecordClass(Enum):
    IN = 0x0001


class OwnerNodeType(Enum):
    B_NODE = 0b00
    P_NODE = 0b01
    M_NODE = 0b10
    RESERVED = 0b11


@dataclass
class NBFlags:
    """
                                             1   1   1   1   1   1
     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   | G |  ONT  |                RESERVED                           |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    """
    g: bool
    ont: OwnerNodeType

    def pack(self) -> bytes:
        assert False # Broken
        resource_record_net_bios_flags: int = 0b1 if self.g else 0b0
        resource_record_net_bios_flags |= self.ont.value << 1
        return struct.pack("<H", resource_record_net_bios_flags)

    @classmethod
    def unpack(cls, data: bytes) -> "NBFlags":
        if len(data) != 2:
            raise ValueError("NBFlags field must be 16 bits (2 bytes) in length")
        data_int: int = struct.unpack("!H", data)[0]
        g = bool(data_int >> 15)
        ont = OwnerNodeType((data_int >> 13) & 0b11)
        return cls(g, ont)


# Will likely need to find another home but placing it here for the time being
@dataclass
class IPv4Address:
    address: str

    def pack(self) -> bytes:
        address_bytes: bytes = b""
        octets: List[str] = self.address.split(".")
        if len(octets) != 4:
            raise ValueError(f'"{self.address}" is not a valid IPv4 address')
        for octet in octets:
            address_bytes += struct.pack("!b", octet)
        return address_bytes

    @classmethod
    def unpack(cls, data: bytes) -> "IPv4Address":
        if len(data) != 4:
            raise ValueError(f'An IPv4 address must be exactly 4 bytes in length')
        address: str = ".".join([str(octet) for octet in data])
        return cls(address)


@dataclass
class NBRData:
    nb_flags: NBFlags
    nb_address: IPv4Address

    def pack(self) -> bytes:
        return self.nb_flags.pack() + self.nb_address.pack()

    @classmethod
    def unpack(cls, data: bytes) -> "NBRData":
        if len(data) != 6:
            raise ValueError("NB_RDATA field must be exatly 6 bytes in length")
        nb_flags: NBFlags = NBFlags.unpack(data[0:2])
        nb_address: IPv4Address = IPv4Address.unpack(data[2:])
        return cls(nb_flags, nb_address)


@dataclass
class ResourceRecord:
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
    r_data: Optional[NBRData]

    def pack(self) -> bytes:
        rr_name_bytes: bytes = self.rr_name.encoded_netbios_name
        rr_type_bytes: bytes = struct.pack("!H", self.rr_type.value)
        rr_class_bytes: bytes = struct.pack("!H", self.rr_class.value)
        ttl_bytes = struct.pack("!Q", self.rr_class.value)
        rd_length_bytes: bytes = struct.pack("!H", self.rd_length)
        resource_record_bytes: bytes = (
            rr_name_bytes + rr_type_bytes + rr_class_bytes + ttl_bytes + rd_length_bytes
        )
        if self.r_data is not None:
            if self.rr_type != ResourceRecordType.NB:
                raise ValueError(
                    'RDATA fields are only present for resoruce records of type "NB"'
                )
            r_data_bytes: bytes = self.r_data.pack()
            resource_record_bytes += r_data_bytes
        return resource_record_bytes

    @classmethod
    def unpack(cls, data: bytes) -> "ResourceRecord":
        return cls.unpack_from_start_of_data(data)[0]

    @classmethod
    def unpack_from_start_of_data(
        cls, data: bytes
    ) -> Tuple["ResourceRecord", int]:
        last_byte_of_rr_name_index: int = data.index(b"\x00")
        rr_name_bytes: bytes = data[:last_byte_of_rr_name_index + 1]
        rr_name = NetBIOSName(rr_name_bytes)
        rr_type_bytes: bytes = data[
            last_byte_of_rr_name_index + 1 : last_byte_of_rr_name_index + 3
        ]
        rr_type = ResourceRecordType(struct.unpack("!H", rr_type_bytes)[0])
        rr_class_bytes: bytes = data[
            last_byte_of_rr_name_index + 3 : last_byte_of_rr_name_index + 5
        ]
        rr_class = ResourceRecordClass(struct.unpack("!H", rr_class_bytes)[0])
        ttl_class_bytes: bytes = data[
            last_byte_of_rr_name_index + 5 : last_byte_of_rr_name_index + 9
        ]
        ttl: int = struct.unpack("!I", ttl_class_bytes)[0]
        rd_length_bytes: bytes = data[
            last_byte_of_rr_name_index + 9 : last_byte_of_rr_name_index + 11
        ]
        rd_length: int = struct.unpack("!H", rd_length_bytes)[0]
        total_record_length: int = last_byte_of_rr_name_index + 11
        if rr_type == ResourceRecordType.NB:
            r_data_bytes: bytes = data[
                last_byte_of_rr_name_index + 11 : last_byte_of_rr_name_index + 17
            ]
            r_data: NBRData = NBRData.unpack(r_data_bytes)
            total_record_length = last_byte_of_rr_name_index + 17
        return (
            cls(rr_name, rr_type, rr_class, ttl, rd_length, r_data),
            total_record_length,
        )


@dataclass
class NameServicePacket:
    """
                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    + ------                                                ------- +
    |                            HEADER                             |
    + ------                                                ------- +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    /                       QUESTION ENTRIES                        /
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    /                    ANSWER RESOURCE RECORDS                    /
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    /                  AUTHORITY RESOURCE RECORDS                   /
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    /                  ADDITIONAL RESOURCE RECORDS                  /
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    header: NameServicePacketHeader
    question_entries: List[NameServivceQuestionEntry]
    answer_resource_records: List[ResourceRecord]
    authority_resource_records: List[ResourceRecord]
    additional_resource_records: List[ResourceRecord]

    def pack(self) -> bytes:
        packet: bytes = b""
        packet += self.header.pack()
        for question_entry in self.question_entries:
            packet += question_entry.pack()
        for answer_resource_record in self.answer_resource_records:
            packet += answer_resource_record.pack()
        for authority_resource_record in self.authority_resource_records:
            packet += authority_resource_record.pack()
        for additional_resource_record in self.additional_resource_records:
            packet += additional_resource_record.pack()
        return packet

    @classmethod
    def unpack(cls, data: bytes) -> "NameServicePacket":
        header: NameServicePacketHeader = NameServicePacketHeader.unpack(data[0:12])
        current_offset: int = 12
        # This can be simplified

        # Pack Question Entries
        question_entries: List[NameServivceQuestionEntry] = []
        for _ in range(header.qdcount):
            question_entry, entry_length = NameServivceQuestionEntry.unpack_from_start_of_data(data[current_offset:])
            current_offset += entry_length
            question_entries.append(question_entry)

        # Pack Answer Entries
        answer_entries: List[ResourceRecord] = []
        for _ in range(header.ancount):
            answer_entry, entry_length = ResourceRecord.unpack_from_start_of_data(data[current_offset:])
            current_offset += entry_length
            answer_entries.append(answer_entry)

        # Pack Authroity Entries
        authority_entries: List[ResourceRecord] = []
        for _ in range(header.nscount):
            authority_entry, entry_length = ResourceRecord.unpack_from_start_of_data(data[current_offset:])
            current_offset += entry_length
            authority_entries.append(authority_entry)

        # Pack Additional Entries
        additional_entries: List[ResourceRecord] = []
        for _ in range(header.arcount):
            additional_entry, entry_length = ResourceRecord.unpack_from_start_of_data(data[current_offset:])
            current_offset += entry_length
            additional_entries.append(additional_entry)
        return cls(header, question_entries, answer_entries, authority_entries, additional_entries)
