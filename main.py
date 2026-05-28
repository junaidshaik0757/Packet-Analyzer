#!/usr/bin/env python3
"""
main.py - CLI entry point for the DPI Engine (Python port).

Usage:
    python main.py <input.pcap> <output.pcap> [options]

Options:
    --block-app   <AppName>    Block all traffic of this app type
                               (e.g. YouTube, Facebook, TikTok, Netflix)
    --block-ip    <IP>         Block all traffic from this source IP
    --block-domain <substring> Block any flow whose SNI contains this text
    --help                     Show this message

Examples:
    python main.py capture.pcap filtered.pcap
    python main.py capture.pcap filtered.pcap --block-app YouTube --block-app TikTok
    python main.py capture.pcap filtered.pcap --block-ip 192.168.1.50
    python main.py capture.pcap filtered.pcap --block-domain facebook --block-domain tiktok
"""

import sys
import argparse

from dpi_types import AppType
from rule_manager import RuleManager
from dpi_engine   import DPIEngine


def parse_args():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="DPI Engine — Deep Packet Inspection (Python port)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input_pcap",  help="Input PCAP file path")
    parser.add_argument("output_pcap", help="Output PCAP file path (allowed traffic only)")
    parser.add_argument(
        "--block-app", metavar="APP", action="append", default=[],
        help="App to block (e.g. YouTube, Facebook, TikTok, Netflix, Twitter, Instagram)"
    )
    parser.add_argument(
        "--block-ip", metavar="IP", action="append", default=[],
        help="Source IP to block"
    )
    parser.add_argument(
        "--block-domain", metavar="DOMAIN", action="append", default=[],
        help="Domain substring to block"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Build rules
    rules = RuleManager()

    for app_name in args.block_app:
        try:
            app = AppType[app_name.upper()]
            rules.block_app(app)
        except KeyError:
            valid = ", ".join(a.name for a in AppType if a != AppType.UNKNOWN)
            print(f"[ERROR] Unknown app '{app_name}'. Valid values: {valid}")
            sys.exit(1)

    for ip in args.block_ip:
        rules.block_ip(ip)

    for domain in args.block_domain:
        rules.block_domain(domain)

    # Run engine
    engine = DPIEngine(rules=rules)
    try:
        engine.process(args.input_pcap, args.output_pcap)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        raise


if __name__ == "__main__":
    main()