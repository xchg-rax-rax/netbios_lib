import pytest
from netbios_name import *


def test_first_level_encode_rfc_example_1() -> None:
    netbios_name: str = "The NetBIOS name"
    scope: str = "SCOPE.ID.COM"
    correct_first_level_encoding: str = "FEGIGFCAEOGFHEECEJEPFDCAGOGBGNGF.SCOPE.ID.COM"
    assert (
        NetBIOSName.first_level_encode(netbios_name, scope)
        == correct_first_level_encoding
    )


def test_first_level_encode_rfc_example_2() -> None:
    netbios_name: str = "FRED" + " " * 12
    scope: str = "NETBIOS.COM"
    correct_first_level_encoding: str = "EGFCEFEECACACACACACACACACACACACA.NETBIOS.COM"
    assert (
        NetBIOSName.first_level_encode(netbios_name, scope)
        == correct_first_level_encoding
    )


def test_second_level_encode_rfc_example() -> None:
    domain_name: str = "EGFCEFEECACACACACACACACACACACACA.NETBIOS.COM"
    correct_second_level_encoding: bytes = (
        b"\x20EGFCEFEECACACACACACACACACACACACA\x07NETBIOS\x03COM\x00"
    )
    assert NetBIOSName.second_level_encode(domain_name) == correct_second_level_encoding


def test_second_level_encode_label_too_long() -> None:
    domain_name: str = (
        "EGFCEFEECACACACACACACACACACACACAEGFCEFEECACACACACACACACACACACACA.NETBIOS.COM"
    )
    correct_second_level_encoding: bytes = (
        b"\x20EGFCEFEECACACACACACACACACACACACA\x07NETBIOS\x03COM\x00"
    )
    try:
        NetBIOSName.second_level_encode(domain_name)
    except ValueError as e:
        assert str(e).startswith("Candidate label")
        return
    assert False


def test_second_level_encode_domain_too_long() -> None:
    domain_name: str = (
        "EGFCEFEECACACACACACACACACACACACA.NETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOS.NETBIOS.NETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOS.NETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOS.NETBIOS.NETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOSNETBIOSNETBIOS.NETBIOS.NETBIOS.COM"
    )
    try:
        NetBIOSName.second_level_encode(domain_name)
    except ValueError as e:
        assert str(e).startswith("Encoded domain name")
        return
    assert False
