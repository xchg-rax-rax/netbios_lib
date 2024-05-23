from typing import List, Optional
from dataclasses import dataclass
import struct

@dataclass
class NetBIOSName:
    encoded_netbios_name: bytes

    @classmethod
    def build_from_string(cls, netbios_name: str, scope_id: str) -> "NetBIOSName":
        first_level_encoded: str = cls.first_level_encode(netbios_name, scope_id)
        second_level_encoded: bytes = cls.second_level_encode(first_level_encoded)
        return cls(second_level_encoded)

    @staticmethod
    def first_level_encode(netbios_name: str, scope_id: str) -> str:
        encoded_name: str = ""
        for c in netbios_name:
            c_ord: int = ord(c)
            lower_nibble: int = c_ord & 0xF
            upper_nibble: int = (c_ord & 0xF0) >> 4
            encoded_name += chr(upper_nibble + ord("A"))
            encoded_name += chr(lower_nibble + ord("A"))
        return encoded_name + "." + scope_id

    @staticmethod
    def second_level_encode(domain_name: str) -> bytes:
        encoded_domain_name: bytes = b""
        labels: List[str] = domain_name.split(".")
        for label in labels:
            label_bytes: bytes = label.encode("utf-8")
            label_length: int = len(label_bytes)
            if label_length > 63:
                raise ValueError(f'Candidate label "{label}" is longer than 63 bytes')
            encoded_domain_name += struct.pack("B", label_length)
            encoded_domain_name += label_bytes
        encoded_domain_name += b"\x00"
        print(len(encoded_domain_name))
        if len(encoded_domain_name) > 255:
            raise ValueError(
                f'Encoded domain name "{domain_name}" exceeds maximum permissible length of 255 bytes'
            )
        return encoded_domain_name

