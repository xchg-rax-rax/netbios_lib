import pytest
from nameservice_packet import *


def test_nameservice_packet_header_unpack_real_query() -> None:
    ns_packet_header_bytes: bytes = b"\x1c`\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00"
    ns_packet_header: NameServicePacketHeader = NameServicePacketHeader.unpack(
        ns_packet_header_bytes
    )
    assert ns_packet_header.name_trn_id == 0x1C60
    assert not ns_packet_header.r
    assert ns_packet_header.opcode == Opcode.QUERY
    assert not ns_packet_header.nm_flags.AA
    assert not ns_packet_header.nm_flags.TC
    assert ns_packet_header.nm_flags.RD
    assert not ns_packet_header.nm_flags.RA
    assert ns_packet_header.nm_flags.B
    assert ns_packet_header.rcode == RCode.NO_ERR
    assert ns_packet_header.qdcount == 0x1
    assert ns_packet_header.ancount == 0x0
    assert ns_packet_header.nscount == 0x0
    assert ns_packet_header.arcount == 0x0


def test_nameservice_packet_header_unpack_real_response() -> None:
    ns_packet_header_bytes: bytes = b"\x7fH\x85\x80\x00\x00\x00\x01\x00\x00\x00\x00"
    ns_packet_header: NameServicePacketHeader = NameServicePacketHeader.unpack(
        ns_packet_header_bytes
    )
    assert ns_packet_header.name_trn_id == 0x7F48
    assert ns_packet_header.r
    assert ns_packet_header.opcode == Opcode.QUERY
    assert ns_packet_header.nm_flags.AA
    assert not ns_packet_header.nm_flags.TC
    assert ns_packet_header.nm_flags.RD
    assert ns_packet_header.nm_flags.RA
    assert not ns_packet_header.nm_flags.B
    assert ns_packet_header.rcode == RCode.NO_ERR
    assert ns_packet_header.qdcount == 0x0
    assert ns_packet_header.ancount == 0x1
    assert ns_packet_header.nscount == 0x0
    assert ns_packet_header.arcount == 0x0


def test_unpack_resource_record() -> None:
    resource_record_bytes: bytes = (
        b" ENFJFDEFFCFGEFFCCACACACACACACACA\x00\x00 \x00\x01\x00\x03\xf4\x80\x00\x06\x00\x00\xc0\xa8z\x01"
    )
    resource_record: ResourceRecord = ResourceRecord.unpack(resource_record_bytes)
    print(resource_record.rr_name.encoded_netbios_name)
    assert resource_record.rr_name == NetBIOSName.build_from_string("MYSERVER", "")
    assert resource_record.rr_type == ResourceRecordType.NB
    assert resource_record.rr_class == ResourceRecordClass.IN


def test_namservice_packet_query() -> None:
    ns_query_packet_bytes: bytes = (
        b"\x1c`\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00 EMEPEDEBEMEIEPFDFECACACACACACAAA\x00\x00 \x00\x01"
    )
    ns_query_packet: NameServicePacket = NameServicePacket.unpack(ns_query_packet_bytes)
    # Verify Header
    assert ns_query_packet.header.name_trn_id == 0x1C60
    assert not ns_query_packet.header.r
    assert ns_query_packet.header.opcode == Opcode.QUERY
    assert not ns_query_packet.header.nm_flags.AA
    assert not ns_query_packet.header.nm_flags.TC
    assert ns_query_packet.header.nm_flags.RD
    assert not ns_query_packet.header.nm_flags.RA
    assert ns_query_packet.header.nm_flags.B
    assert ns_query_packet.header.qdcount == 1
    assert ns_query_packet.header.ancount == 0
    assert ns_query_packet.header.nscount == 0
    assert ns_query_packet.header.arcount == 0
    # Verify Question Entries
    assert len(ns_query_packet.question_entries) == 1
    # assert ns_query_packet.question_entries[0].question_name == NetBIOSName.build_from_string("LOCALHOST")
    assert ns_query_packet.question_entries[0].question_type == QuestionType.NB
    assert ns_query_packet.question_entries[0].question_class == QuestionClass.IN
    # Verify Answer Records
    assert len(ns_query_packet.answer_resource_records) == 0
    # Verify Authority Records
    assert len(ns_query_packet.authority_resource_records) == 0
    # Verify Additional Records
    assert len(ns_query_packet.additional_resource_records) == 0


def test_nameservice_packet_response() -> None:
    ns_query_packet_bytes: bytes = (
        b"\x7fH\x85\x80\x00\x00\x00\x01\x00\x00\x00\x00 ENFJFDEFFCFGEFFCCACACACACACACACA\x00\x00 \x00\x01\x00\x03\xf4\x80\x00\x06\x00\x00\xc0\xa8z\x01"
    )
    ns_query_packet: NameServicePacket = NameServicePacket.unpack(ns_query_packet_bytes)
    assert ns_query_packet.header.name_trn_id == 0x7F48
    assert ns_query_packet.header.r
    assert ns_query_packet.header.opcode == Opcode.QUERY
    assert ns_query_packet.header.nm_flags.AA
    assert not ns_query_packet.header.nm_flags.TC
    assert ns_query_packet.header.nm_flags.RD
    assert ns_query_packet.header.nm_flags.RA
    assert not ns_query_packet.header.nm_flags.B
    assert ns_query_packet.header.rcode == RCode.NO_ERR
    assert ns_query_packet.header.qdcount == 0
    assert ns_query_packet.header.ancount == 1
    assert ns_query_packet.header.nscount == 0
    assert ns_query_packet.header.arcount == 0
    # Verify Question Entries
    assert len(ns_query_packet.question_entries) == 0
    # Verify Answer Records
    assert len(ns_query_packet.answer_resource_records) == 1
    assert ns_query_packet.answer_resource_records[
        0
    ].rr_name == NetBIOSName.build_from_string("MYSERVER")
    assert ns_query_packet.answer_resource_records[0].rr_type == ResourceRecordType.NB
    assert ns_query_packet.answer_resource_records[0].rr_class == ResourceRecordClass.IN
    assert ns_query_packet.answer_resource_records[0].ttl == 0x3F480
    assert ns_query_packet.answer_resource_records[0].rd_length == 6
    assert ns_query_packet.answer_resource_records[0].r_data != None
    assert not ns_query_packet.answer_resource_records[0].r_data.nb_flags.g
    assert (
        ns_query_packet.answer_resource_records[0].r_data.nb_flags.ont
        == OwnerNodeType.B_NODE
    )
    assert ns_query_packet.answer_resource_records[0].r_data.nb_address == IPv4Address(
        "192.168.122.1"
    )
    # Verify Authority Records
    assert len(ns_query_packet.authority_resource_records) == 0
    # Verify Additional Records
    assert len(ns_query_packet.additional_resource_records) == 0
