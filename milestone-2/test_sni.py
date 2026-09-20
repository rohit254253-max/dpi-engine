"""Edge-case tests: bad data must return None and never crash."""
from sni_extractor import extract_sni, extract_http_host
import generate_test_pcap as g  # noqa: F401 (also regenerates pcap, harmless)

good = g.client_hello("www.youtube.com")
assert extract_sni(good) == "www.youtube.com"
assert extract_sni(b"") is None
assert extract_sni(b"\x16\x03\x01") is None
assert extract_sni(b"hello world, not tls") is None
# Truncate a valid hello at every possible length: must never raise
for i in range(len(good)):
    extract_sni(good[:i])
assert extract_http_host(b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n") == "example.com"
assert extract_http_host(b"random bytes") is None
print("All SNI tests passed")
