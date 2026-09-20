"""Creates test_dpi.pcap with a few hand-built TCP/UDP packets."""
import struct
import time


def eth(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff"):
    m = lambda s: bytes(int(x, 16) for x in s.split(":"))
    return m(dst) + m(src) + struct.pack("!H", 0x0800)


def ipv4(src, dst, proto, payload_len):
    ip = lambda s: bytes(int(x) for x in s.split("."))
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, 0, 0, 64, proto, 0, ip(src), ip(dst))


def tcp(sport, dport, flags, payload=b""):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0)
    return hdr + payload


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def build(src, dst, sport, dport, proto, l4):
    return eth() + ipv4(src, dst, proto, len(l4)) + l4


packets = [
    build("192.168.1.100", "172.217.14.206", 54321, 443, 6, tcp(54321, 443, 0x02)),            # SYN
    build("172.217.14.206", "192.168.1.100", 443, 54321, 6, tcp(443, 54321, 0x12)),            # SYN-ACK
    build("192.168.1.100", "172.217.14.206", 54321, 443, 6, tcp(54321, 443, 0x10, b"hello")),  # data
    build("192.168.1.100", "8.8.8.8", 40000, 53, 17, udp(40000, 53, b"dnsquery")),             # DNS
]

with open("test_dpi.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    now = int(time.time())
    for i, p in enumerate(packets):
        f.write(struct.pack("<IIII", now, i * 1000, len(p), len(p)))
        f.write(p)
print(f"Wrote test_dpi.pcap with {len(packets)} packets")
