"""Extract the domain name from TLS Client Hello (SNI) or HTTP Host header.

Every read is bounds-checked: network data can be truncated or garbage,
so a malformed packet must return None, never crash.
"""
from typing import Optional

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def extract_sni(payload: bytes) -> Optional[str]:
    """Return the SNI hostname from a TLS Client Hello, else None."""
    # --- TLS record header (5 bytes) ---
    if len(payload) < 9:
        return None
    if payload[0] != 0x16:            # 0x16 = Handshake
        return None
    if payload[1] != 0x03:            # TLS major version is always 3
        return None
    if payload[5] != 0x01:            # handshake type 0x01 = Client Hello
        return None

    # Skip: record hdr(5) + handshake hdr(4) + version(2) + random(32) = 43
    pos = 43
    if pos >= len(payload):
        return None

    # Session ID
    pos += 1 + payload[pos]

    # Cipher suites (2-byte length)
    if pos + 2 > len(payload):
        return None
    pos += 2 + int.from_bytes(payload[pos:pos + 2], "big")

    # Compression methods (1-byte length)
    if pos + 1 > len(payload):
        return None
    pos += 1 + payload[pos]

    # Extensions block (2-byte total length)
    if pos + 2 > len(payload):
        return None
    ext_total = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    end = min(pos + ext_total, len(payload))

    # Walk extensions: type(2) + length(2) + data
    while pos + 4 <= end:
        ext_type = int.from_bytes(payload[pos:pos + 2], "big")
        ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
        pos += 4
        if pos + ext_len > end:
            return None
        if ext_type == 0x0000:        # SNI extension
            # list_len(2) + name_type(1) + name_len(2) + name
            if ext_len < 5:
                return None
            name_type = payload[pos + 2]
            name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
            if name_type != 0 or pos + 5 + name_len > end:
                return None
            try:
                return payload[pos + 5:pos + 5 + name_len].decode("ascii")
            except UnicodeDecodeError:
                return None
        pos += ext_len
    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """Return the Host header from a plain HTTP request, else None."""
    if not payload.startswith(HTTP_METHODS):
        return None
    for line in payload.split(b"\r\n")[1:]:
        if line == b"":
            break                     # end of headers
        if line.lower().startswith(b"host:"):
            host = line[5:].strip().decode("ascii", errors="ignore")
            return host.split(":")[0] or None   # drop :port
    return None


def extract_domain(payload: bytes) -> Optional[str]:
    """Try TLS SNI first, then HTTP Host."""
    return extract_sni(payload) or extract_http_host(payload)
