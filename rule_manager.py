"""
rule_manager.py - Manage blocking rules (IP, app-type, domain).
Equivalent to include/rule_manager.h in the C++ version.

Supports three rule types:
  - IP blacklist     : block all traffic from a source IP
  - App blacklist    : block all traffic of a detected AppType
  - Domain blacklist : block any flow whose SNI contains a substring
"""

from typing import Set, List, Optional
from dpi_types import AppType


class RuleManager:
    """Holds all active blocking rules and evaluates packets against them."""

    def __init__(self):
        self._blocked_ips:     Set[str]     = set()
        self._blocked_apps:    Set[AppType] = set()
        self._blocked_domains: List[str]    = []   # substring match

    # ── Add rules ─────────────────────────────────────────────────────────

    def block_ip(self, ip: str):
        """Block all traffic originating from this IP address."""
        self._blocked_ips.add(ip.strip())
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app: AppType):
        """Block all traffic classified as this application type."""
        self._blocked_apps.add(app)
        print(f"[Rules] Blocked app: {app.name}")

    def block_domain(self, domain: str):
        """Block any flow whose SNI contains this substring (case-insensitive)."""
        self._blocked_domains.append(domain.lower().strip())
        print(f"[Rules] Blocked domain pattern: {domain}")

    # ── Query ─────────────────────────────────────────────────────────────

    def is_blocked(
        self,
        src_ip:   str,
        app_type: AppType,
        sni:      str = "",
    ) -> bool:
        """Return True if this flow should be dropped."""
        if src_ip in self._blocked_ips:
            return True
        if app_type in self._blocked_apps:
            return True
        if sni:
            sni_lower = sni.lower()
            for pattern in self._blocked_domains:
                if pattern in sni_lower:
                    return True
        return False

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def blocked_ips(self) -> Set[str]:
        return frozenset(self._blocked_ips)

    @property
    def blocked_apps(self) -> Set[AppType]:
        return frozenset(self._blocked_apps)

    @property
    def blocked_domains(self) -> List[str]:
        return list(self._blocked_domains)

    def has_rules(self) -> bool:
        return bool(self._blocked_ips or self._blocked_apps or self._blocked_domains)

    def summary(self) -> str:
        lines = []
        if self._blocked_ips:
            lines.append(f"  IPs      : {', '.join(sorted(self._blocked_ips))}")
        if self._blocked_apps:
            lines.append(f"  Apps     : {', '.join(a.name for a in self._blocked_apps)}")
        if self._blocked_domains:
            lines.append(f"  Domains  : {', '.join(self._blocked_domains)}")
        return "\n".join(lines) if lines else "  (none)"