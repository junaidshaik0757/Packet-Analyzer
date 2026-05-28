"""
types.py - Core data structures for the DPI Engine.
Equivalent to include/types.h and src/types.cpp
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional
import struct


class AppType(Enum):
    UNKNOWN    = auto()
    HTTP       = auto()
    HTTPS      = auto()
    DNS        = auto()
    GOOGLE     = auto()
    YOUTUBE    = auto()
    FACEBOOK   = auto()
    TWITTER    = auto()
    INSTAGRAM  = auto()
    TIKTOK     = auto()
    NETFLIX    = auto()
    AMAZON     = auto()
    GITHUB     = auto()
    CLOUDFLARE = auto()
    MICROSOFT  = auto()
    APPLE      = auto()
    TWITCH     = auto()
    REDDIT     = auto()
    WIKIPEDIA  = auto()
    DISCORD    = auto()


# Maps SNI substrings → AppType (order matters — most specific first)
SNI_PATTERNS: list[tuple[str, AppType]] = [
    ("youtube",     AppType.YOUTUBE),
    ("googlevideo", AppType.YOUTUBE),
    ("ytimg",       AppType.YOUTUBE),
    ("facebook",    AppType.FACEBOOK),
    ("fbcdn",       AppType.FACEBOOK),
    ("instagram",   AppType.INSTAGRAM),
    ("cdninstagram",AppType.INSTAGRAM),
    ("tiktok",      AppType.TIKTOK),
    ("musical.ly",  AppType.TIKTOK),
    ("netflix",     AppType.NETFLIX),
    ("nflxvideo",   AppType.NETFLIX),
    ("amazon",      AppType.AMAZON),
    ("twitch",      AppType.TWITCH),
    ("reddit",      AppType.REDDIT),
    ("discord",     AppType.DISCORD),
    ("twitter",     AppType.TWITTER),
    ("t.co",        AppType.TWITTER),
    ("wikipedia",   AppType.WIKIPEDIA),
    ("github",      AppType.GITHUB),
    ("microsoft",   AppType.MICROSOFT),
    ("windows",     AppType.MICROSOFT),
    ("apple",       AppType.APPLE),
    ("icloud",      AppType.APPLE),
    ("cloudflare",  AppType.CLOUDFLARE),
    ("google",      AppType.GOOGLE),
    ("gstatic",     AppType.GOOGLE),
    ("googleapis",  AppType.GOOGLE),
    ("gmail",       AppType.GOOGLE),
]


def sni_to_app_type(sni: str) -> AppType:
    """Map a hostname/SNI string to an AppType."""
    if not sni:
        return AppType.UNKNOWN
    lower = sni.lower()
    for pattern, app in SNI_PATTERNS:
        if pattern in lower:
            return app
    return AppType.UNKNOWN


@dataclass(frozen=True, eq=True)
class FiveTuple:
    """Uniquely identifies a network flow (connection)."""
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: int   # 6=TCP, 17=UDP

    def __str__(self):
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else str(self.protocol)
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} [{proto}]"


@dataclass
class Flow:
    """State for a single network connection/flow."""
    tuple:         FiveTuple = None
    sni:           str       = ""
    host:          str       = ""          # HTTP Host header
    app_type:      AppType   = AppType.UNKNOWN
    blocked:       bool      = False
    packet_count:  int       = 0
    byte_count:    int       = 0
    classified:    bool      = False       # True once SNI/host found


@dataclass
class RawPacket:
    """Raw bytes + metadata from PCAP."""
    ts_sec:   int   = 0
    ts_usec:  int   = 0
    data:     bytes = b""
    orig_len: int   = 0

    @property
    def timestamp(self) -> float:
        return self.ts_sec + self.ts_usec / 1_000_000


@dataclass
class ParsedPacket:
    """Protocol-decoded packet fields."""
    # Ethernet
    src_mac:  str = ""
    dst_mac:  str = ""
    eth_type: int = 0

    # IP
    src_ip:   str = ""
    dst_ip:   str = ""
    protocol: int = 0
    ttl:      int = 0
    ip_id:    int = 0

    # TCP/UDP
    src_port: int = 0
    dst_port: int = 0
    has_tcp:  bool = False
    has_udp:  bool = False
    tcp_flags: int = 0
    seq:       int = 0
    ack:       int = 0

    # Payload
    payload:  bytes = b""

    # Derived
    raw:      RawPacket = None
    five_tuple: FiveTuple = None

    def build_five_tuple(self) -> FiveTuple:
        self.five_tuple = FiveTuple(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
        )
        return self.five_tuple