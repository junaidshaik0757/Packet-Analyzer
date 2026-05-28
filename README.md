# DPI Engine — Deep Packet Inspection (Python)

A full Python port of [perryvegehan/Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer), a Deep Packet Inspection system that reads network captures (PCAP files), classifies traffic by application, applies blocking rules, and writes filtered output.

---

## What is DPI?

**Deep Packet Inspection (DPI)** looks *inside* network packets — not just headers (IPs/ports), but the actual payload. Even HTTPS traffic leaks the destination hostname in the TLS handshake (the **SNI field**), enabling application-level classification without breaking encryption.

```
User Traffic (PCAP) → [DPI Engine] → Filtered Output (PCAP)
                           ↓
                    - Identifies apps (YouTube, TikTok, Netflix ...)
                    - Blocks by IP / app / domain pattern
                    - Generates a detailed traffic report
```

---

## Project Structure

```
packet_analyzer/
├── main.py                  ← CLI entry point
├── dpi_engine.py            ← Main orchestrator
├── dpi_types.py             ← Data structures: FiveTuple, Flow, AppType, RawPacket
├── pcap_reader.py           ← PCAP file reader & writer
├── packet_parser.py         ← Ethernet / IPv4 / TCP / UDP parser
├── sni_extractor.py         ← TLS SNI + HTTP Host extraction
├── rule_manager.py          ← IP / app / domain blocking rules
├── generate_test_pcap.py    ← Generates a realistic test PCAP
└── test_dpi.pcap            ← Pre-generated sample traffic
```

---

## Prerequisites

- Python **3.10+**
- No third-party libraries required — pure standard library

---

## Quick Start

### 1. Generate a test PCAP

```bash
python generate_test_pcap.py
# creates test_dpi.pcap with 57 packets across 18 flows
```

### 2. Run without any blocking (analyze only)

```bash
python main.py test_dpi.pcap output.pcap
```

### 3. Run with blocking rules

```bash
# Block by app
python main.py test_dpi.pcap output.pcap --block-app YOUTUBE

# Block multiple apps
python main.py test_dpi.pcap output.pcap --block-app YOUTUBE --block-app TIKTOK

# Block a specific source IP
python main.py test_dpi.pcap output.pcap --block-ip 192.168.1.50

# Block by domain substring
python main.py test_dpi.pcap output.pcap --block-domain facebook

# Combine all rule types
python main.py test_dpi.pcap output.pcap --block-app YOUTUBE --block-app TIKTOK --block-ip 192.168.1.50 --block-domain facebook
```

---

## Available App Names

```
YOUTUBE  FACEBOOK  INSTAGRAM  TIKTOK   NETFLIX   AMAZON
GOOGLE   GITHUB    TWITTER    DISCORD  REDDIT    WIKIPEDIA
MICROSOFT  APPLE   CLOUDFLARE  TWITCH  HTTP  HTTPS  DNS
```

---

## Sample Output

```
[Rules] Blocked app: YOUTUBE
[Rules] Blocked app: TIKTOK
[Rules] Blocked IP: 192.168.1.50

══════════════════════════════════════════════════════════════════
                     DPI Engine v2.0 (Python)
══════════════════════════════════════════════════════════════════
[Reader] Processing test_dpi.pcap ...
[Reader] Done — 57 packets in 0.001s

══════════════════════════════════════════════════════════════════
                        PROCESSING REPORT
══════════════════════════════════════════════════════════════════
  Total Packets                          57
  Total Bytes                         8,757
  TCP Packets                            53
  UDP Packets                             4
  Unique Flows                           18
──────────────────────────────────────────────────────────────────
  Forwarded                              49
  Dropped                                 8
──────────────────────────────────────────────────────────────────
  ACTIVE BLOCKING RULES
    IPs      : 192.168.1.50
    Apps     : YOUTUBE, TIKTOK
──────────────────────────────────────────────────────────────────
  APPLICATION BREAKDOWN

  GOOGLE               8   14.0%  ██░░░░░░░░░░░░░░░░░░
  GITHUB               6   10.5%  ██░░░░░░░░░░░░░░░░░░
  YOUTUBE (BLOCKED)    6   10.5%  ██░░░░░░░░░░░░░░░░░░
  TIKTOK  (BLOCKED)    4    7.0%  █░░░░░░░░░░░░░░░░░░░
  DNS                  4    7.0%  █░░░░░░░░░░░░░░░░░░░
──────────────────────────────────────────────────────────────────
  DETECTED DOMAINS / SNIs

  www.youtube.com          → YOUTUBE    ✗ BLOCKED
  www.tiktok.com           → TIKTOK     ✗ BLOCKED
  www.google.com           → GOOGLE     ✓
  www.facebook.com         → FACEBOOK   ✓
══════════════════════════════════════════════════════════════════
```

---

## How It Works

### Packet journey

```
Raw PCAP bytes
     │
     ▼  pcap_reader.py
RawPacket (ts_sec, ts_usec, data bytes)
     │
     ▼  packet_parser.py
ParsedPacket  ← Ethernet / IPv4 / TCP / UDP headers decoded
     │
     ▼  FiveTuple lookup
Flow (per-connection state: sni, app_type, blocked flag, counters)
     │
     ▼  sni_extractor.py
SNI string  ← TLS Client Hello parsed byte-by-byte
              OR HTTP "Host:" header for plaintext HTTP
     │
     ▼  dpi_types.py → sni_to_app_type()
AppType (YOUTUBE, FACEBOOK, TIKTOK, DNS, HTTP, HTTPS, UNKNOWN ...)
     │
     ▼  rule_manager.py
is_blocked(src_ip, app_type, sni)?
     │
     ├── YES → Dropped  (not written to output)
     └── NO  → Forwarded (written to output.pcap)
```

### SNI extraction (the key insight)

HTTPS is encrypted — but the very first packet of a TLS connection (the **Client Hello**) contains the target hostname in plaintext as the **SNI** extension:

```
TLS Record (byte 0 = 0x16 Handshake)
  └── Client Hello (byte 5 = 0x01)
        └── Extensions
              └── SNI Extension (type 0x0000)
                    └── "www.youtube.com"   ← extracted here
```

### Five-tuple flow tracking

Each unique connection is identified by:

| Field | Example |
|---|---|
| Source IP | 192.168.1.100 |
| Destination IP | 172.217.14.206 |
| Source Port | 54321 |
| Destination Port | 443 |
| Protocol | TCP (6) |

All packets sharing a five-tuple belong to the same flow. Once blocked, **all subsequent packets** of that flow are dropped.

### Blocking rules

| Rule | Flag | Example | What it blocks |
|---|---|---|---|
| App type | `--block-app` | `YOUTUBE` | All YouTube flows |
| Source IP | `--block-ip` | `192.168.1.50` | All traffic from this IP |
| Domain pattern | `--block-domain` | `tiktok` | Any SNI containing "tiktok" |

---

## Extending the Project

To add a new app (e.g. Spotify), open `dpi_types.py` and add:

```python
class AppType(Enum):
    ...
    SPOTIFY = auto()

SNI_PATTERNS = [
    ...
    ("spotify", AppType.SPOTIFY),
    ("scdn.co", AppType.SPOTIFY),
]
```

Then block it with:

```bash
python main.py input.pcap output.pcap --block-app SPOTIFY
```

---

## Use Your Own PCAP

Capture traffic with Wireshark or `tcpdump`, then run:

```bash
python main.py my_capture.pcap filtered.pcap --block-app TIKTOK
```

Supports both little-endian and big-endian PCAP files automatically.

---

## Comparison with Original C++ Version

| Feature | C++ original | Python port |
|---|---|---|
| PCAP reading | Custom binary reader | `pcap_reader.py` (same approach) |
| Protocol parsing | Manual byte offsets | `packet_parser.py` (same approach) |
| SNI extraction | Byte-level TLS parser | `sni_extractor.py` (same approach) |
| Flow tracking | `std::unordered_map` | Python `dict` with `FiveTuple` key |
| Multi-threading | LB + FP thread pools | Single-threaded |
| Blocking rules | `rule_manager.h` | `rule_manager.py` |
| Dependencies | `libpcap` | None (stdlib only) |