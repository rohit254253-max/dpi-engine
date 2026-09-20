"""Milestone 2: read a PCAP, parse packets, and show the domain (SNI / HTTP Host)."""
import sys
from pcap_reader import PcapReader
import packet_parser
import sni_extractor

PROTO = {6: "TCP", 17: "UDP"}


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py input.pcap")
        sys.exit(1)

    total = parsed = found = 0
    with PcapReader(sys.argv[1]) as reader:
        for raw in reader.packets():
            total += 1
            p = packet_parser.parse(raw.data)
            if p is None:
                continue
            parsed += 1
            domain = sni_extractor.extract_domain(p.payload) if p.payload else None
            if domain:
                found += 1
            tag = f"  [{domain}]" if domain else ""
            print(f"#{total:<3} {PROTO.get(p.protocol, p.protocol)}  "
                  f"{p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port}  "
                  f"payload={len(p.payload)}B{tag}")
    print(f"\nTotal: {total} | Parsed: {parsed} | Domains found: {found}")


if __name__ == "__main__":
    main()
