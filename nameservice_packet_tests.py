import pytest
from nameservice_packet import *


def test_nameservice_packet_header_pack_trivial() -> None:
    ns_packet_header = NameServicePacketHeader(
        name_trn_id=0,
        r=False,
        opcode=Opcode.QUERY,
        nm_flags=NMFlags(AA=False, TC=False, RD=False, RA=False, B=False),
        rcode=RCode.NO_ERR,
        qdcount=0,
        adcount=0,
        nscount=0,
        arcount=0,
    )
    ns_packet_header_bytes: bytes = ns_packet_header.pack()
    assert ns_packet_header_bytes == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_nameservice_packet_header_pack_non_trivial() -> None:
    ns_packet_header = NameServicePacketHeader(
        name_trn_id=128,
        r=False,
        opcode=Opcode.REFRESH,
        nm_flags=NMFlags(AA=True, TC=True, RD=False, RA=True, B=True),
        rcode=RCode.FMT_ERR,
        qdcount=12,
        adcount=1024,
        nscount=16,
        arcount=99,
    )
    ns_packet_header_bytes: bytes = ns_packet_header.pack()
    assert ns_packet_header_bytes == b"\x00\x80\x70\x19\x00\x0c\x04\x00\x00\x10\x00\x63"


def test_nameservice_packet_header_pack_invalid_id() -> None:
    ns_packet_header = NameServicePacketHeader(
        name_trn_id=128123,
        r=False,
        opcode=Opcode.REFRESH,
        nm_flags=NMFlags(AA=True, TC=True, RD=False, RA=True, B=True),
        rcode=RCode.FMT_ERR,
        qdcount=12,
        adcount=1024,
        nscount=16,
        arcount=99,
    )
    try:
        _ = ns_packet_header.pack()
    except ValueError:
        return
    # Should have thrown an exception
    assert False

def test_nameservice_packet_header_unpack_trivial() -> None:
    ns_packet_header_bytes: bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    unpacked_ns_packet_header: NameServicePacketHeader = NameServicePacketHeader.unpack(
        ns_packet_header_bytes
    )
    correct_ns_packet_header = NameServicePacketHeader(
        name_trn_id=0,
        r=False,
        opcode=Opcode.QUERY,
        nm_flags=NMFlags(AA=False, TC=False, RD=False, RA=False, B=False),
        rcode=RCode.NO_ERR,
        qdcount=0,
        adcount=0,
        nscount=0,
        arcount=0,
    )
    assert unpacked_ns_packet_header == correct_ns_packet_header

def test_nameservice_packet_unpack_non_trivial() -> None:
    ns_packet_header_bytes: bytes = b"\x00\x80\x70\x19\x00\x0c\x04\x00\x00\x10\x00\x63"
    unpacked_ns_packet_header: NameServicePacketHeader = NameServicePacketHeader.unpack(
        ns_packet_header_bytes
    )
    correct_ns_packet_header = NameServicePacketHeader(
        name_trn_id=128,
        r=False,
        opcode=Opcode.REFRESH,
        nm_flags=NMFlags(AA=True, TC=True, RD=False, RA=True, B=True),
        rcode=RCode.FMT_ERR,
        qdcount=12,
        adcount=1024,
        nscount=16,
        arcount=99,
    )
    assert unpacked_ns_packet_header == correct_ns_packet_header

