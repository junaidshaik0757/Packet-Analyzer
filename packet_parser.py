"""
packet_parser.py - Decode Ethernet / IP / TCP / UDP headers from raw bytes.
Equivalent to include/packet_parser.h + src/packet_parser.cpp

Packet layout (Ethernet frame):
  [0 -  5]  Destination MAC  (6 bytes)
  [6 - 11]  Source MAC       (6 bytes)
  [12- 13]  EtherType        (2 bytes)  0x0800=IPv4, 0x86DD=IPv6
  [14- 33]  IPv4 Header      (20+ bytes, variable IHL)
  [varies]  TCP Header       (20+ bytes) or UDP (8 bytes)
  [varies]  Payload
"""

import struct
from typing import Optional
from dpi_types import RawPacket, ParsedPacket, FiveTuple

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP  = 0x0806

PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

ETH_HDR_LEN = 14


def _mac(data: bytes, offset: int) -> str:
    return ":".join(f"{b:02x}" for b in data[offset:offset+6])


def _ip(b: bytes) -> str:
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


class PacketParser:
    """Static helper — parse a RawPacket into a ParsedPacket."""

    @staticmethod
    def parse(raw: RawPacket) -> Optional[ParsedPacket]:
        data = raw.data
        if len(data) < ETH_HDR_LEN:
            return None

        pkt = ParsedPacket(raw=raw)

        # ── Ethernet ──────────────────────────────────────────────────────
        pkt.dst_mac  = _mac(data, 0)
        pkt.src_mac  = _mac(data, 6)
        pkt.eth_type = struct.unpack(">H", data[12:14])[0]

        if pkt.eth_type != ETHERTYPE_IPV4:
            return pkt   # We only deeply inspect IPv4

        # ── IPv4 ──────────────────────────────────────────────────────────
        if len(data) < ETH_HDR_LEN + 20:
            return pkt

        ip_offset = ETH_HDR_LEN
        ihl       = (data[ip_offset] & 0x0F) * 4     # header length in bytes
        pkt.ttl      = data[ip_offset + 8]
        pkt.protocol = data[ip_offset + 9]
        pkt.ip_id    = struct.unpack(">H", data[ip_offset+4:ip_offset+6])[0]
        pkt.src_ip   = _ip(data[ip_offset+12:ip_offset+16])
        pkt.dst_ip   = _ip(data[ip_offset+16:ip_offset+20])

        transport_offset = ip_offset + ihl

        # ── TCP ───────────────────────────────────────────────────────────
        if pkt.protocol == PROTO_TCP:
            if len(data) < transport_offset + 20:
                return pkt
            pkt.has_tcp  = True
            pkt.src_port = struct.unpack(">H", data[transport_offset:transport_offset+2])[0]
            pkt.dst_port = struct.unpack(">H", data[transport_offset+2:transport_offset+4])[0]
            pkt.seq      = struct.unpack(">I", data[transport_offset+4:transport_offset+8])[0]
            pkt.ack      = struct.unpack(">I", data[transport_offset+8:transport_offset+12])[0]
            tcp_data_offset = ((data[transport_offset+12] >> 4) & 0xF) * 4
            pkt.tcp_flags   = data[transport_offset+13]
            payload_start   = transport_offset + tcp_data_offset
            pkt.payload     = data[payload_start:]

        # ── UDP ───────────────────────────────────────────────────────────
        elif pkt.protocol == PROTO_UDP:
            if len(data) < transport_offset + 8:
                return pkt
            pkt.has_udp  = True
            pkt.src_port = struct.unpack(">H", data[transport_offset:transport_offset+2])[0]
            pkt.dst_port = struct.unpack(">H", data[transport_offset+2:transport_offset+4])[0]
            pkt.payload  = data[transport_offset+8:]

        pkt.build_five_tuple()
        return pkt