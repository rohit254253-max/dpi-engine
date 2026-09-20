"""PCAP file reader (classic libpcap format, no external libs)."""
import struct
from dataclasses import dataclass
from typing import Iterator

# Magic numbers tell us the byte order of the file
MAGIC_LE = 0xA1B2C3D4   # written little-endian
MAGIC_BE = 0xD4C3B2A1   # written big-endian


@dataclass
class RawPacket:
    ts_sec: int
    ts_usec: int
    orig_len: int
    data: bytes


class PcapReader:
    def __init__(self, path: str):
        self.path = path
        self._f = None
        self._endian = "<"
        self.link_type = None

    def __enter__(self):
        self._f = open(self.path, "rb")
        hdr = self._f.read(24)
        if len(hdr) < 24:
            raise ValueError("File too short to be a PCAP")
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic == MAGIC_LE:
            self._endian = "<"
        elif magic == MAGIC_BE:
            self._endian = ">"
        else:
            raise ValueError(f"Not a PCAP file (magic=0x{magic:08x})")
        # version_major, version_minor, thiszone, sigfigs, snaplen, network
        _, _, _, _, _, self.link_type = struct.unpack(self._endian + "HHiIII", hdr[4:])
        return self

    def __exit__(self, *exc):
        if self._f:
            self._f.close()

    def packets(self) -> Iterator[RawPacket]:
        while True:
            hdr = self._f.read(16)
            if len(hdr) < 16:
                return  # clean EOF
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(self._endian + "IIII", hdr)
            data = self._f.read(incl_len)
            if len(data) < incl_len:
                return  # truncated file
            yield RawPacket(ts_sec, ts_usec, orig_len, data)
