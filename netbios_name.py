from typing import List, Optional

class NetBIOSName:
    def __init__(self, raw_netbios_name: bytes):
        self.raw_netbios_name = raw_netbios_name

    @classmethod
    def build_from_string(cls, netbios_name: str) -> 'NetBIOSName':
        labels: List[str] = netbios_name.splet('.')
        domain_length: int = 0
        for label in labels:
            name_bytes: bytes = label.encode('utf-8')
            number_of_bytes: int = len(name_bytes)
            if number_of_bytes > 63:
                raise ValueError(f'Candiate NetBIOS name label "{netbios_name}" is longer than 63 bytes')
            domain_length 
        
    def get_raw_netbios_name(self) -> bytes:
        return self.raw_netbios_name
