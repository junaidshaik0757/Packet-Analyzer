"""
dpi_engine.py - Deep Packet Inspection Engine (Python port).

Architecture mirrors main_working.cpp (single-threaded) from the C++ original:

  PcapReader  →  PacketParser  →  SNIExtractor  →  RuleManager  →  PcapWriter
                                       ↑
                               HTTPHostExtractor

For each packet:
  1. Read raw bytes from PCAP
  2. Parse Ethernet / IP / TCP / UDP headers
  3. Look up (or create) the 5-tuple flow
  4. If HTTPS (dst_port 443): try TLS SNI extraction
     If HTTP  (dst_port 80):  try HTTP Host extraction
     If DNS   (dst_port 53):  mark as DNS
  5. Map SNI/host → AppType
  6. Check blocking rules
  7. Forward (write to output) or drop
  8. Print report

Usage:
    python dpi_engine.py <input.pcap> <output.pcap> [options]
"""

import sys
import time
from collections import defaultdict
from typing import Dict, Optional

from dpi_types         import RawPacket, ParsedPacket, FiveTuple, Flow, AppType, sni_to_app_type
from pcap_reader    import PcapReader, PcapWriter
from packet_parser  import PacketParser
from sni_extractor  import SNIExtractor, HTTPHostExtractor
from rule_manager   import RuleManager


# ── ANSI colour helpers ───────────────────────────────────────────────────────

def _c(code: str, text: str) -> str:
    """Wrap text in ANSI colour code (no-op on Windows without ANSI support)."""
    return f"\033[{code}m{text}\033[0m"

GREEN  = lambda t: _c("32", t)
RED    = lambda t: _c("31", t)
YELLOW = lambda t: _c("33", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)


# ── DPI Engine ────────────────────────────────────────────────────────────────

class DPIEngine:
    """
    Single-threaded Deep Packet Inspection engine.
    Reads a PCAP, classifies traffic, applies blocking rules,
    writes allowed packets to output, and prints a detailed report.
    """

    def __init__(self, rules: Optional[RuleManager] = None):
        self.rules   = rules or RuleManager()
        self.flows:  Dict[FiveTuple, Flow] = {}

        # Statistics
        self.total_packets = 0
        self.total_bytes   = 0
        self.tcp_packets   = 0
        self.udp_packets   = 0
        self.forwarded     = 0
        self.dropped       = 0

    # ── Classification ────────────────────────────────────────────────────

    def _classify(self, pkt: ParsedPacket, flow: Flow):
        """
        Attempt to extract SNI or HTTP Host from packet payload.
        Sets flow.sni, flow.host, flow.app_type, flow.classified.
        """
        if flow.classified or not pkt.payload:
            return

        payload = pkt.payload

        # TLS / HTTPS — look for SNI in Client Hello
        if pkt.dst_port == 443 or pkt.src_port == 443:
            sni = SNIExtractor.extract(payload)
            if sni:
                flow.sni        = sni
                flow.app_type   = sni_to_app_type(sni)
                flow.classified = True
                if flow.app_type == AppType.UNKNOWN:
                    flow.app_type = AppType.HTTPS
                return
            # If no SNI yet but destination is 443, at least tag as HTTPS
            if pkt.dst_port == 443 and flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.HTTPS
            return

        # Plain HTTP
        if pkt.dst_port == 80 or pkt.src_port == 80:
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.host       = host
                flow.sni        = host
                flow.app_type   = sni_to_app_type(host)
                flow.classified = True
                if flow.app_type == AppType.UNKNOWN:
                    flow.app_type = AppType.HTTP
            elif flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.HTTP
            return

        # DNS
        if pkt.dst_port == 53 or pkt.src_port == 53:
            if flow.app_type == AppType.UNKNOWN:
                flow.app_type = AppType.DNS
            return

    # ── Processing ────────────────────────────────────────────────────────

    def process(self, input_path: str, output_path: str):
        """
        Main entry point: process all packets from input_path,
        write allowed ones to output_path.
        """
        start = time.time()
        print(self._banner())

        with PcapReader(input_path) as reader, PcapWriter(output_path) as writer:
            print(f"{CYAN('[Reader]')} Processing {input_path} ...")

            for raw in reader.packets():
                self.total_packets += 1
                self.total_bytes   += len(raw.data)

                # Parse headers
                pkt = PacketParser.parse(raw)
                if pkt is None or pkt.eth_type != 0x0800:
                    # Not IPv4 — forward as-is
                    writer.write(raw)
                    self.forwarded += 1
                    continue

                if pkt.five_tuple is None:
                    writer.write(raw)
                    self.forwarded += 1
                    continue

                # Stats
                if pkt.has_tcp:
                    self.tcp_packets += 1
                elif pkt.has_udp:
                    self.udp_packets += 1

                # Get or create flow
                ft = pkt.five_tuple
                if ft not in self.flows:
                    flow = Flow(tuple=ft)
                    self.flows[ft] = flow
                else:
                    flow = self.flows[ft]

                flow.packet_count += 1
                flow.byte_count   += len(raw.data)

                # If already blocked, drop immediately
                if flow.blocked:
                    self.dropped += 1
                    continue

                # Classify (extract SNI / Host)
                self._classify(pkt, flow)

                # Check rules
                if self.rules.is_blocked(ft.src_ip, flow.app_type, flow.sni):
                    flow.blocked = True
                    self.dropped += 1
                    continue

                # Forward
                writer.write(raw)
                self.forwarded += 1

        elapsed = time.time() - start
        print(f"{CYAN('[Reader]')} Done — {self.total_packets} packets in {elapsed:.3f}s\n")
        self._print_report()

    # ── Report ────────────────────────────────────────────────────────────

    def _banner(self) -> str:
        width = 66
        lines = [
            "═" * width,
            f"{'DPI Engine v2.0 (Python)':^{width}}",
            "═" * width,
        ]
        return "\n".join(lines)

    def _print_report(self):
        W = 66
        rule_summary = self.rules.summary()

        # App statistics
        app_counts: Dict[AppType, int] = defaultdict(int)
        detected_domains: Dict[str, AppType] = {}
        for flow in self.flows.values():
            app_counts[flow.app_type] += flow.packet_count
            if flow.sni or flow.host:
                key = flow.sni or flow.host
                detected_domains[key] = flow.app_type

        sorted_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)

        # Build report
        sep = "═" * W
        thin = "─" * W

        print(sep)
        print(f"{'PROCESSING REPORT':^{W}}")
        print(sep)
        print(f"  {'Total Packets':<30} {self.total_packets:>10,}")
        print(f"  {'Total Bytes':<30} {self.total_bytes:>10,}")
        print(f"  {'TCP Packets':<30} {self.tcp_packets:>10,}")
        print(f"  {'UDP Packets':<30} {self.udp_packets:>10,}")
        print(f"  {'Unique Flows':<30} {len(self.flows):>10,}")
        print(thin)
        print(f"  {GREEN('Forwarded'):<39} {self.forwarded:>10,}")
        print(f"  {RED('Dropped'):<39} {self.dropped:>10,}")
        print(thin)

        # Blocking rules active
        if self.rules.has_rules():
            print(f"  {'ACTIVE BLOCKING RULES'}")
            for line in rule_summary.split("\n"):
                print(f"  {line}")
            print(thin)

        # Application breakdown
        print(f"  {'APPLICATION BREAKDOWN'}")
        print()
        total_pkts = max(self.total_packets, 1)
        bar_width  = 20
        for app, count in sorted_apps:
            pct     = count / total_pkts * 100
            bars    = int(pct / 100 * bar_width)
            bar_str = "█" * bars + "░" * (bar_width - bars)
            blocked = app in self.rules.blocked_apps
            label   = f"{app.name:<14}"
            if blocked:
                label = RED(label) + RED("  (BLOCKED)")
            line = f"  {label}  {count:>6,}  {pct:5.1f}%  {bar_str}"
            print(line)

        print(thin)

        # Detected domains / SNIs
        if detected_domains:
            print(f"  {'DETECTED DOMAINS / SNIs'}")
            print()
            for domain, app in sorted(detected_domains.items()):
                blocked = app in self.rules.blocked_apps or self.rules.is_blocked("", app, domain)
                status  = RED("  ✗ BLOCKED") if blocked else GREEN("  ✓")
                print(f"  {domain:<40} → {app.name:<14}{status}")

        print(sep)
        print()