"""
pcap_reader.py - Read and write PCAP files.
Supports both little-endian (0xa1b2c3d4) and big-endian (0xd4c3b2a1) PCAP files.
"""

import struct
from typing import Generator
from dpi_types import RawPacket

PCAP_MAGIC_LE    = 0xa1b2c3d4   # little-endian native
PCAP_MAGIC_BE    = 0xd4c3b2a1   # big-endian (byte-swapped)
PCAP_MAGIC_NS_LE = 0xa1b23c4d   # nanosecond little-endian
PCAP_MAGIC_NS_BE = 0x4d3cb2a1   # nanosecond big-endian


class PcapReader:
    """Reads packets from a PCAP file — handles both endiannesses."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file    = None
        self._endian  = "<"      # '<' little, '>' big
        self._ns_mode = False
        self._open()

    def _open(self):
        self._file = open(self.filepath, "rb")
        raw = self._file.read(24)
        if len(raw) < 24:
            raise ValueError(f"File too small to be a PCAP: {self.filepath}")

        # Read magic as both endiannesses to detect which one it is
        magic_le = struct.unpack_from("<I", raw, 0)[0]
        magic_be = struct.unpack_from(">I", raw, 0)[0]

        if magic_le in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            self._endian  = "<"
            self._ns_mode = (magic_le == PCAP_MAGIC_NS_LE)
        elif magic_be in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE) or magic_le == PCAP_MAGIC_BE:
            self._endian  = ">"
            self._ns_mode = (magic_le == PCAP_MAGIC_NS_BE)
        else:
            raise ValueError(
                f"Not a valid PCAP file — unrecognised magic: 0x{magic_le:08x}"
            )

        fmt = self._endian + "IHHiIII"
        magic, maj, min_, tz, sig, snaplen, network = struct.unpack(fmt, raw)
        self.version = (maj, min_)
        self.snaplen = snaplen
        self.network = network

    def packets(self) -> Generator[RawPacket, None, None]:
        """Yield RawPacket objects for every packet in the file."""
        fmt      = self._endian + "IIII"
        hdr_size = struct.calcsize(fmt)
        while True:
            raw = self._file.read(hdr_size)
            if not raw or len(raw) < hdr_size:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, raw)
            data = self._file.read(incl_len)
            if len(data) < incl_len:
                break
            yield RawPacket(
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                data=data,
                orig_len=orig_len,
            )

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class PcapWriter:
    """Writes packets to a PCAP file (always little-endian)."""

    GLOBAL_HEADER = struct.pack(
        "<IHHiIII",
        PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, 1,
    )

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file    = open(filepath, "wb")
        self._file.write(self.GLOBAL_HEADER)

    def write(self, pkt: RawPacket):
        hdr = struct.pack(
            "<IIII",
            pkt.ts_sec, pkt.ts_usec,
            len(pkt.data), pkt.orig_len,
        )
        self._file.write(hdr)
        self._file.write(pkt.data)

    def close(self):
        if self._file:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()