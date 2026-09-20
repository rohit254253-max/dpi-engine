"""Parse Ethernet -> IPv4 -> TCP/UDP headers using struct."""
import struct
from dataclasses import dataclass
from typing import Optional

ETH_LEN = 14
ETHERTYPE_IPV4 = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass
class ParsedPacket:
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    tcp_flags: int = 0
    payload: bytes = b""

    @property
    def five_tuple(self):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def parse(data: bytes) -> Optional[ParsedPacket]:
    """Return ParsedPacket, or None if not IPv4 TCP/UDP (or malformed)."""
    if len(data) < ETH_LEN:
        return None
    pkt = ParsedPacket(dst_mac=_mac(data[0:6]), src_mac=_mac(data[6:12]))

    ethertype = struct.unpack("!H", data[12:14])[0]
    if ethertype != ETHERTYPE_IPV4:
        return None

    # --- IPv4 header ---
    ip = data[ETH_LEN:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4          # header length in bytes
    if ihl < 20 or len(ip) < ihl:
        return None
    pkt.protocol = ip[9]
    pkt.src_ip = _ip(ip[12:16])
    pkt.dst_ip = _ip(ip[16:20])

    l4 = ip[ihl:]
    if pkt.protocol == PROTO_TCP:
        if len(l4) < 20:
            return None
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", l4[0:4])
        data_off = (l4[12] >> 4) * 4   # TCP header length
        if data_off < 20 or len(l4) < data_off:
            return None
        pkt.tcp_flags = l4[13]
        pkt.payload = l4[data_off:]
    elif pkt.protocol == PROTO_UDP:
        if len(l4) < 8:
            return None
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", l4[0:4])
        pkt.payload = l4[8:]
    else:
        return None
    return pkt
