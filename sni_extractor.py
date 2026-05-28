"""
sni_extractor.py - Extract domain names from TLS SNI and HTTP Host headers.
Equivalent to include/sni_extractor.h + src/sni_extractor.cpp

TLS Client Hello layout:
  Byte  0   : Content Type     (0x16 = Handshake)
  Bytes 1-2 : Version          (e.g. 0x0301)
  Bytes 3-4 : Record Length
  Byte  5   : Handshake Type   (0x01 = Client Hello)
  Bytes 6-8 : Handshake Length
  Bytes 9-10: Client Version
  Bytes 11-42: Random           (32 bytes)
  Byte 43   : Session ID Length (N)
  ...        : Session ID       (N bytes)
  2 bytes   : Cipher Suites Length (M)
  ...        : Cipher Suites    (M bytes)
  1 byte    : Compression Methods Length (C)
  ...        : Compression Methods (C bytes)
  2 bytes   : Extensions Length
  per extension:
    2 bytes : Extension Type
    2 bytes : Extension Data Length
    ...     : Extension Data
  SNI extension type = 0x0000
    2 bytes : SNI List Length
    1 byte  : Name Type (0x00 = hostname)
    2 bytes : Name Length (K)
    K bytes : Hostname string
"""

import struct
from typing import Optional


TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_EXT_SNI = 0x0000


def _u16be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">H", data, offset)[0]


class SNIExtractor:
    """Extract the SNI (Server Name Indication) from a TLS Client Hello."""

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """
        Return the SNI hostname string, or None if not found / not a ClientHello.
        """
        if len(payload) < 43:
            return None

        # TLS record header
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return None
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        offset = 43  # start of Session ID Length

        try:
            # Skip Session ID
            if offset >= len(payload):
                return None
            session_len = payload[offset]
            offset += 1 + session_len

            # Skip Cipher Suites
            if offset + 2 > len(payload):
                return None
            cipher_len = _u16be(payload, offset)
            offset += 2 + cipher_len

            # Skip Compression Methods
            if offset + 1 > len(payload):
                return None
            comp_len = payload[offset]
            offset += 1 + comp_len

            # Extensions length
            if offset + 2 > len(payload):
                return None
            ext_total_len = _u16be(payload, offset)
            offset += 2

            ext_end = offset + ext_total_len

            # Walk extensions
            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = _u16be(payload, offset)
                ext_data_len = _u16be(payload, offset + 2)
                offset += 4

                if ext_type == TLS_EXT_SNI:
                    # SNI list length (2) + name type (1) + name length (2) = 5
                    if offset + 5 > len(payload):
                        return None
                    # sni_list_len = _u16be(payload, offset)  # skip
                    # name_type   = payload[offset + 2]       # 0x00 = hostname
                    name_len = _u16be(payload, offset + 3)
                    name_start = offset + 5
                    if name_start + name_len > len(payload):
                        return None
                    return payload[name_start:name_start + name_len].decode(
                        "ascii", errors="replace"
                    )

                offset += ext_data_len

        except (IndexError, struct.error):
            return None

        return None


class HTTPHostExtractor:
    """Extract the Host: header from plaintext HTTP requests."""

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        """
        Return the Host header value, or None if not an HTTP request.
        Works with HTTP/1.0 and HTTP/1.1.
        """
        try:
            # Quick check for HTTP methods at the start
            HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ",
                            b"DELETE ", b"OPTIONS ", b"CONNECT ", b"PATCH ")
            if not any(payload.startswith(m) for m in HTTP_METHODS):
                return None

            # Decode as text (Latin-1 is safe for header bytes)
            text = payload.decode("latin-1", errors="replace")

            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line[5:].strip()
                    # Strip port if present
                    if ":" in host:
                        host = host.rsplit(":", 1)[0]
                    return host if host else None

        except Exception:
            pass

        return None