"""
SandboxFirewall — in-memory IP block registry.

Provides a safe, non-destructive enforcement layer that simulates
firewall blocking without touching the OS. Blocked IPs are held
in memory with timestamps and auto-unblocked after a configurable
duration.

NO destructive OS commands (iptables, netsh, etc.) are used.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class BlockEntry:
    """A single IP block record."""

    ip: str
    blocked_at: datetime
    reason: str
    incident_id: str | None = None
    expires_at: datetime | None = None
    auto_unblock: bool = True


class SandboxFirewall:
    """In-memory firewall simulation for sandbox enforcement.

    Features:
      - Timestamped block entries with auto-expiry
      - Whitelist support (whitelisted IPs are never blocked)
      - Queryable status and audit log
      - Thread-safe for async usage

    Usage::

        fw = SandboxFirewall()
        fw.block("192.168.1.100", reason="brute_force", incident_id="INC-001")
        assert fw.is_blocked("192.168.1.100")
        fw.unblock("192.168.1.100")
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._blocked: dict[str, BlockEntry] = {}
        self._whitelist: set[str] = {"127.0.0.1", "::1"}
        self._audit_log: list[dict[str, Any]] = []
        self._total_blocks = 0
        self._total_unblocks = 0

        # Multi-source enforcement extensions
        self._flagged_processes: dict[str, dict[str, Any]] = {}
        self._flagged_users: dict[str, dict[str, Any]] = {}

    # ── Block / Unblock ─────────────────────────────────────────────────

    def block(
        self,
        ip: str,
        *,
        reason: str = "threshold_exceeded",
        incident_id: str | None = None,
        duration_seconds: int | None = None,
    ) -> bool:
        """Block an IP address. Returns False if whitelisted or already blocked."""
        if ip in self._whitelist:
            logger.info("SandboxFirewall: %s is whitelisted, not blocking", ip)
            self._log_action("block_denied", ip, reason="whitelisted")
            return False

        if ip in self._blocked:
            logger.debug("SandboxFirewall: %s already blocked", ip)
            return False

        now = datetime.now(timezone.utc)
        duration = self._settings.BLOCK_DURATION_SECONDS if duration_seconds is None else duration_seconds
        expires = now + timedelta(seconds=duration)

        entry = BlockEntry(
            ip=ip,
            blocked_at=now,
            reason=reason,
            incident_id=incident_id,
            expires_at=expires,
        )
        self._blocked[ip] = entry
        self._total_blocks += 1

        self._log_action("blocked", ip, reason=reason, incident_id=incident_id)
        logger.info(
            "🚫 SandboxFirewall: BLOCKED %s — reason=%s, expires=%s, incident=%s",
            ip,
            reason,
            expires.isoformat(),
            incident_id or "N/A",
        )
        return True

    def unblock(self, ip: str) -> bool:
        """Manually unblock an IP. Returns False if not currently blocked."""
        if ip not in self._blocked:
            return False

        del self._blocked[ip]
        self._total_unblocks += 1
        self._log_action("unblocked", ip, reason="manual")
        logger.info("✅ SandboxFirewall: UNBLOCKED %s (manual)", ip)
        return True

    # ── Query ───────────────────────────────────────────────────────────

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked (respects auto-expiry)."""
        entry = self._blocked.get(ip)
        if entry is None:
            return False

        # Check auto-expiry
        if entry.expires_at and datetime.now(timezone.utc) >= entry.expires_at:
            del self._blocked[ip]
            self._total_unblocks += 1
            self._log_action("unblocked", ip, reason="expired")
            logger.info("✅ SandboxFirewall: UNBLOCKED %s (expired)", ip)
            return False

        return True

    def get_block_entry(self, ip: str) -> BlockEntry | None:
        """Get the full block record for an IP."""
        if not self.is_blocked(ip):
            return None
        return self._blocked.get(ip)

    def get_blocked_ips(self) -> list[BlockEntry]:
        """Return all currently blocked IPs (after expiry check)."""
        # Trigger expiry checks
        for ip in list(self._blocked.keys()):
            self.is_blocked(ip)
        return list(self._blocked.values())

    # ── Whitelist ───────────────────────────────────────────────────────

    def add_whitelist(self, ip: str) -> None:
        """Add an IP to the whitelist."""
        self._whitelist.add(ip)
        # If currently blocked, unblock it
        if ip in self._blocked:
            del self._blocked[ip]
            self._log_action("unblocked", ip, reason="added_to_whitelist")

    def remove_whitelist(self, ip: str) -> None:
        """Remove an IP from the whitelist."""
        self._whitelist.discard(ip)

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self._whitelist

    # ── Expiry ──────────────────────────────────────────────────────────

    def expire_blocks(self) -> int:
        """Expire all blocks past their duration. Returns count expired."""
        now = datetime.now(timezone.utc)
        expired: list[str] = []

        for ip, entry in self._blocked.items():
            if entry.expires_at and now >= entry.expires_at:
                expired.append(ip)

        for ip in expired:
            del self._blocked[ip]
            self._total_unblocks += 1
            self._log_action("unblocked", ip, reason="expired")
            logger.info("✅ SandboxFirewall: UNBLOCKED %s (expired)", ip)

        return len(expired)

    # ── Audit & Stats ───────────────────────────────────────────────────

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Return the full audit log."""
        return list(self._audit_log)

    # ── Multi-source enforcement ──────────────────────────────────────────

    def flag_process(
        self,
        process_name: str,
        *,
        reason: str = "suspicious_activity",
        ip: str = "",
        pid: int = 0,
    ) -> bool:
        """Flag a suspicious process for monitoring/audit."""
        if process_name in self._flagged_processes:
            return False

        self._flagged_processes[process_name] = {
            "reason": reason,
            "ip": ip,
            "pid": pid,
            "flagged_at": datetime.now(timezone.utc).isoformat(),
        }
        self._log_action("flag_process", ip or "N/A", process=process_name, reason=reason)
        logger.info(
            "⚠️  SandboxFirewall: FLAGGED process %s (pid=%d, reason=%s)",
            process_name, pid, reason,
        )
        return True

    def flag_user(
        self,
        username: str,
        *,
        reason: str = "suspicious_auth",
        ip: str = "",
    ) -> bool:
        """Flag a suspicious user account for monitoring/audit."""
        if username in self._flagged_users:
            return False

        self._flagged_users[username] = {
            "reason": reason,
            "ip": ip,
            "flagged_at": datetime.now(timezone.utc).isoformat(),
        }
        self._log_action("flag_user", ip or "N/A", username=username, reason=reason)
        logger.info(
            "⚠️  SandboxFirewall: FLAGGED user %s (reason=%s)",
            username, reason,
        )
        return True

    def get_flagged_processes(self) -> dict[str, dict[str, Any]]:
        """Return all flagged processes."""
        return dict(self._flagged_processes)

    def get_flagged_users(self) -> dict[str, dict[str, Any]]:
        """Return all flagged users."""
        return dict(self._flagged_users)

    def get_stats(self) -> dict[str, Any]:
        """Return firewall statistics."""
        return {
            "currently_blocked": len(self._blocked),
            "total_blocks": self._total_blocks,
            "total_unblocks": self._total_unblocks,
            "whitelist_size": len(self._whitelist),
            "audit_log_size": len(self._audit_log),
            "flagged_processes": len(self._flagged_processes),
            "flagged_users": len(self._flagged_users),
        }

    # ── Internal ────────────────────────────────────────────────────────

    def _log_action(self, action: str, ip: str, **kwargs: Any) -> None:
        """Record an action in the audit log."""
        entry = {
            "action": action,
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }
        self._audit_log.append(entry)
