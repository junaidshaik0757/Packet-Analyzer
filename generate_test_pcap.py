#!/usr/bin/env python3
"""
generate_test_pcap.py - Generate a realistic test PCAP file.

Creates a PCAP with:
  - TLS ClientHello packets to YouTube, Facebook, TikTok, Google, Netflix
  - Plain HTTP traffic to github.com, wikipedia.org
  - DNS UDP queries
  - A blocked source IP (192.168.1.50)
  - Unknown / unclassified traffic

This mirrors generate_test_pcap.py from the original C++ project.

Usage:
    python generate_test_pcap.py [output.pcap]
"""

import struct
import time
import sys
import random

OUTPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else "test_dpi.pcap"


# ── Low-level helpers ─────────────────────────────────────────────────────────

def u16be(n: int) -> bytes:
    return struct.pack(">H", n)

def u32be(n: int) -> bytes:
    return struct.pack(">I", n)

def ip_bytes(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))

def mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


# ── Header builders ───────────────────────────────────────────────────────────

def eth_header(dst: str = "00:11:22:33:44:55",
               src: str = "aa:bb:cc:dd:ee:ff",
               etype: int = 0x0800) -> bytes:
    return mac_bytes(dst) + mac_bytes(src) + u16be(etype)

def ipv4_header(src: str, dst: str, proto: int, payload_len: int,
                ttl: int = 64, pkt_id: int = 0) -> bytes:
    total_len = 20 + payload_len
    hdr = bytes([
        0x45,           # Version=4, IHL=5 (20 bytes)
        0x00,           # DSCP / ECN
    ])
    hdr += u16be(total_len)
    hdr += u16be(pkt_id)           # ID
    hdr += u16be(0x4000)           # Flags: Don't Fragment
    hdr += bytes([ttl, proto])
    hdr += b"\x00\x00"             # Checksum placeholder
    hdr += ip_bytes(src)
    hdr += ip_bytes(dst)
    # Recompute checksum
    s = 0
    for i in range(0, 20, 2):
        s += (hdr[i] << 8) | hdr[i+1]
    s = (s >> 16) + (s & 0xFFFF)
    s = ~s & 0xFFFF
    return hdr[:10] + struct.pack(">H", s) + hdr[12:]

def tcp_header(src_port: int, dst_port: int,
               seq: int = 0, ack: int = 0,
               flags: int = 0x18) -> bytes:   # PSH+ACK
    hdr = u16be(src_port) + u16be(dst_port)
    hdr += u32be(seq) + u32be(ack)
    hdr += bytes([0x50, flags])    # Data offset=5 (20 bytes), flags
    hdr += u16be(65535)            # Window
    hdr += b"\x00\x00\x00\x00"    # Checksum + Urgent
    return hdr

def udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    total = 8 + payload_len
    return u16be(src_port) + u16be(dst_port) + u16be(total) + b"\x00\x00"


# ── TLS Client Hello builder ──────────────────────────────────────────────────

def tls_client_hello(sni: str) -> bytes:
    """Build a minimal but structurally valid TLS 1.2 Client Hello with SNI."""
    sni_bytes = sni.encode("ascii")
    sni_ext = (
        u16be(0x0000) +                      # Extension type: SNI
        u16be(len(sni_bytes) + 5) +          # Extension length
        u16be(len(sni_bytes) + 3) +          # SNI list length
        b"\x00" +                            # Name type: host_name
        u16be(len(sni_bytes)) +              # Name length
        sni_bytes                            # The hostname
    )

    # Add a few more harmless extensions to look realistic
    extra_exts = (
        u16be(0x000f) + u16be(1) + b"\x01"   # heartbeat
    )

    extensions = sni_ext + extra_exts

    # Cipher suites (just a few)
    cipher_suites = b"\xc0\x2c\xc0\x2b\x00\x9c\x00\x9d"

    client_hello_body = (
        b"\x03\x03" +                        # Client version: TLS 1.2
        bytes(32) +                          # Random (32 zero bytes)
        b"\x00" +                            # Session ID length: 0
        u16be(len(cipher_suites)) +
        cipher_suites +
        b"\x01\x00" +                        # Compression methods: 1, null
        u16be(len(extensions)) +
        extensions
    )

    handshake = (
        b"\x01" +                            # Handshake type: Client Hello
        b"\x00" + u16be(len(client_hello_body))[1:] +   # 3-byte length
        client_hello_body
    )

    # Wait — 3-byte length:
    hs_len = len(client_hello_body)
    handshake = (
        b"\x01" +
        bytes([(hs_len >> 16) & 0xFF, (hs_len >> 8) & 0xFF, hs_len & 0xFF]) +
        client_hello_body
    )

    record = (
        b"\x16" +                            # Content type: Handshake
        b"\x03\x01" +                        # TLS version: 1.0
        u16be(len(handshake)) +
        handshake
    )
    return record


# ── HTTP request builder ──────────────────────────────────────────────────────

def http_get(host: str, path: str = "/") -> bytes:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    return req.encode("latin-1")


# ── DNS query builder ─────────────────────────────────────────────────────────

def dns_query(domain: str) -> bytes:
    txid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH",
        txid,  # Transaction ID
        0x0100, 1, 0, 0, 0  # Flags: standard query, 1 question
    )
    parts = domain.split(".")
    question = b""
    for part in parts:
        question += bytes([len(part)]) + part.encode()
    question += b"\x00"          # Root label
    question += b"\x00\x01"      # QTYPE: A
    question += b"\x00\x01"      # QCLASS: IN
    return header + question


# ── Full packet assembler ─────────────────────────────────────────────────────

_pkt_id = 0

def make_packet(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    proto: int,                          # 6=TCP, 17=UDP
    payload: bytes,
) -> bytes:
    global _pkt_id
    _pkt_id += 1

    eth = eth_header()

    if proto == 6:   # TCP
        tcp = tcp_header(src_port, dst_port, seq=random.randint(0, 2**32-1))
        transport = tcp + payload
    else:            # UDP
        transport = udp_header(src_port, dst_port, len(payload)) + payload

    ip = ipv4_header(src_ip, dst_ip, proto,
                     len(transport), pkt_id=_pkt_id)
    return eth + ip + transport


# ── PCAP file writer ──────────────────────────────────────────────────────────

def pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII",
        0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def pcap_packet(data: bytes, ts: float) -> bytes:
    sec  = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(data), len(data)) + data


# ── Traffic scenarios ─────────────────────────────────────────────────────────

SCENARIOS = [
    # (src_ip, dst_ip, dst_port, sni_or_host, proto, count, description)
    ("192.168.1.100", "172.217.14.206",   443, "www.youtube.com",    6,  4, "YouTube HTTPS"),
    ("192.168.1.100", "157.240.20.35",    443, "www.facebook.com",   6,  3, "Facebook HTTPS"),
    ("192.168.1.101", "104.244.42.65",    443, "www.twitter.com",    6,  3, "Twitter HTTPS"),
    ("192.168.1.101", "142.250.185.206",  443, "www.google.com",     6,  5, "Google HTTPS"),
    ("192.168.1.102", "54.192.64.45",     443, "www.netflix.com",    6,  4, "Netflix HTTPS"),
    ("192.168.1.102", "185.60.216.35",    443, "www.instagram.com",  6,  3, "Instagram HTTPS"),
    ("192.168.1.103", "23.227.38.65",     443, "www.github.com",     6,  4, "GitHub HTTPS"),
    ("192.168.1.103", "140.82.121.4",     443, "api.github.com",     6,  2, "GitHub API HTTPS"),
    ("192.168.1.104", "151.101.1.140",    443, "www.reddit.com",     6,  3, "Reddit HTTPS"),
    ("192.168.1.104", "162.159.36.1",     443, "discord.com",        6,  3, "Discord HTTPS"),
    # HTTP (plaintext)
    ("192.168.1.100", "208.80.153.224",   80,  "www.wikipedia.org",  6,  3, "Wikipedia HTTP"),
    ("192.168.1.102", "185.199.108.153",  80,  "raw.githubusercontent.com", 6, 2, "GitHub raw HTTP"),
    # Blocked source IP
    ("192.168.1.50",  "142.250.185.206",  443, "www.google.com",     6,  3, "Blocked IP"),
    ("192.168.1.50",  "172.217.14.206",   443, "www.youtube.com",    6,  2, "Blocked IP YouTube"),
    # TikTok
    ("192.168.1.105", "172.64.64.1",      443, "www.tiktok.com",     6,  4, "TikTok HTTPS"),
    # DNS
    ("192.168.1.100", "8.8.8.8",          53,  "",                   17, 4, "DNS queries"),
    # Unknown / unclassified (non-443/80/53 traffic)
    ("192.168.1.106", "10.0.0.1",         8080, "",                  6,  3, "Unknown HTTP-alt"),
    ("192.168.1.107", "192.168.1.1",      22,   "",                  6,  2, "SSH"),
]


def generate(output_path: str):
    print(f"Generating test PCAP: {output_path}")
    ts = time.time() - 60   # start 1 minute ago

    packets = []
    for (src_ip, dst_ip, dst_port, sni_or_host, proto, count, desc) in SCENARIOS:
        src_port = random.randint(49152, 65535)
        for i in range(count):
            if dst_port == 443 and sni_or_host:
                # First packet is TLS ClientHello; rest are dummy payloads
                payload = tls_client_hello(sni_or_host) if i == 0 else bytes(random.randint(50, 200))
            elif dst_port == 80 and sni_or_host:
                payload = http_get(sni_or_host) if i == 0 else bytes(random.randint(30, 100))
            elif dst_port == 53 and proto == 17:
                domains = ["www.example.com", "api.service.io", "cdn.example.net", "mail.google.com"]
                payload = dns_query(domains[i % len(domains)])
            else:
                payload = bytes(random.randint(20, 80))

            raw = make_packet(src_ip, dst_ip, src_port, dst_port, proto, payload)
            packets.append((ts, raw))
            ts += random.uniform(0.001, 0.05)

    # Shuffle to simulate interleaved traffic
    random.shuffle(packets)

    with open(output_path, "wb") as f:
        f.write(pcap_global_header())
        for ts_val, data in packets:
            f.write(pcap_packet(data, ts_val))

    print(f"  Written {len(packets)} packets to {output_path}")


if __name__ == "__main__":
    generate(OUTPUT_FILE)