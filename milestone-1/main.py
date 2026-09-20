"""Milestone 1: read a PCAP and print every parsed packet."""
import sys
from pcap_reader import PcapReader
import packet_parser

PROTO = {6: "TCP", 17: "UDP"}


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py input.pcap")
        sys.exit(1)

    total = parsed = 0
    with PcapReader(sys.argv[1]) as reader:
        for raw in reader.packets():
            total += 1
            p = packet_parser.parse(raw.data)
            if p is None:
                continue
            parsed += 1
            print(f"#{total:<3} {PROTO.get(p.protocol, p.protocol)}  "
                  f"{p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port}  "
                  f"payload={len(p.payload)}B")
    print(f"\nTotal: {total} | Parsed (IPv4 TCP/UDP): {parsed}")


if __name__ == "__main__":
    main()
