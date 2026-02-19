"""
NetworkSensor — lightweight network connection monitoring via psutil.

Monitors:
  - New TCP connections per IP
  - Connection rate spikes
  - Outbound traffic to unusual ports
  - Port scanning behaviour (many distinct ports from one IP)

Design constraints:
  - No packet sniffing (no pcap / raw sockets)
  - No root privileges required
  - Uses only ``psutil.net_connections()``
  - Lightweight — polls at configurable interval
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from events.telemetry_event import TelemetryEvent
from telemetry.base_sensor import BaseSensor

logger = logging.getLogger(__name__)

# Ports that are commonly targeted or suspicious for outbound connections
_SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 7777, 8888, 9999,  # common reverse shells
    1337, 31337,  # leet / backdoor
    3389,  # RDP (outbound is suspicious from a server)
    6667, 6697,  # IRC (C2 channel)
    25, 587,  # SMTP (potential spam relay)
}

# Minimum connection count from a single IP to flag as suspicious
_CONN_RATE_THRESHOLD = 15
# Number of distinct ports to flag as port scan
_PORT_SCAN_THRESHOLD = 8


class NetworkSensor(BaseSensor):
    """Monitor network connections for anomalous behaviour.

    Maintains internal state to detect:
      - Connection rate spikes per remote IP
      - Connections to unusual/suspicious ports
      - Port scanning (many distinct ports from one IP)
    """

    def __init__(self, poll_interval: float = 5.0) -> None:
        super().__init__(poll_interval=poll_interval)
        # State: track connections seen per-IP across polls
        self._prev_connections: set[tuple[str, int]] = set()
        self._ip_conn_counts: dict[str, int] = defaultdict(int)
        self._ip_ports: dict[str, set[int]] = defaultdict(set)

    @property
    def name(self) -> str:
        return "network"

    async def _collect_impl(self) -> list[TelemetryEvent]:
        """Poll network connections and detect anomalies."""
        try:
            import psutil
        except ImportError:
            logger.debug("NetworkSensor: psutil not available, skipping")
            return []

        events: list[TelemetryEvent] = []
        now = datetime.now(timezone.utc)

        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, PermissionError):
            logger.debug("NetworkSensor: insufficient permissions")
            return []

        current_conns: set[tuple[str, int]] = set()
        ip_counts: dict[str, int] = defaultdict(int)
        ip_ports: dict[str, set[int]] = defaultdict(set)

        for conn in connections:
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            local_port = conn.laddr.port if conn.laddr else 0

            current_conns.add((remote_ip, remote_port))
            ip_counts[remote_ip] += 1
            ip_ports[remote_ip].add(remote_port)

            # Check for suspicious outbound ports
            if remote_port in _SUSPICIOUS_PORTS:
                events.append(TelemetryEvent(
                    source="network",
                    timestamp=now,
                    event_type="suspicious_port",
                    severity_hint=0.7,
                    ip=remote_ip,
                    raw_payload={
                        "remote_port": remote_port,
                        "local_port": local_port,
                        "direction": "outbound",
                    },
                ))

        # Detect new connections (delta from previous poll)
        new_conns = current_conns - self._prev_connections
        for remote_ip, remote_port in new_conns:
            # Only emit for significant new connections
            if ip_counts[remote_ip] >= 3:
                events.append(TelemetryEvent(
                    source="network",
                    timestamp=now,
                    event_type="new_connection",
                    severity_hint=0.2,
                    ip=remote_ip,
                    raw_payload={
                        "remote_port": remote_port,
                        "total_connections": ip_counts[remote_ip],
                    },
                ))

        # Detect connection rate spikes
        for ip, count in ip_counts.items():
            if count >= _CONN_RATE_THRESHOLD:
                events.append(TelemetryEvent(
                    source="network",
                    timestamp=now,
                    event_type="connection_spike",
                    severity_hint=min(0.4 + (count / 50), 0.9),
                    ip=ip,
                    raw_payload={"connection_count": count},
                ))

        # Detect port scanning (many distinct ports from one IP)
        for ip, ports in ip_ports.items():
            if len(ports) >= _PORT_SCAN_THRESHOLD:
                events.append(TelemetryEvent(
                    source="network",
                    timestamp=now,
                    event_type="port_scan",
                    severity_hint=min(0.6 + (len(ports) / 30), 0.95),
                    ip=ip,
                    raw_payload={
                        "distinct_ports": len(ports),
                        "ports_sample": sorted(list(ports))[:10],
                    },
                ))

        # Update state for next poll
        self._prev_connections = current_conns
        self._ip_conn_counts = dict(ip_counts)
        self._ip_ports = {k: v for k, v in ip_ports.items()}

        return events
