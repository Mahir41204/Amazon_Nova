"""
Synthetic log generators for demo and testing.

Generates realistic security logs for:
  • SSH brute-force attacks
  • Suspicious login patterns
  • Privilege escalation attempts
  • Data exfiltration indicators
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


def generate_brute_force_logs() -> list[str]:
    """Generate realistic SSH brute-force attack log lines.

    Simulates:
      1. A burst of failed SSH logins from a single IP
      2. One successful login
      3. Immediate privilege escalation
      4. Access to sensitive files

    Returns:
        A list of syslog-formatted log strings.
    """
    attacker_ip = "192.168.1.105"
    target_user = "jdoe"
    base_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    logs: list[str] = []

    # Normal background activity
    normal_ips = ["10.0.0.5", "10.0.0.12", "10.0.0.23"]
    for i in range(5):
        ts = base_time + timedelta(seconds=i * 30)
        ip = random.choice(normal_ips)
        logs.append(
            f"{_fmt(ts)} sshd[{random.randint(1000, 9999)}]: "
            f"Accepted publickey for admin from {ip} port {random.randint(40000, 60000)} ssh2"
        )

    # Brute force burst — 47 failed logins in ~3 minutes
    brute_start = base_time + timedelta(minutes=3)
    usernames = ["root", "admin", target_user, "ubuntu", "deploy", "test"]
    for i in range(47):
        ts = brute_start + timedelta(seconds=i * 4 + random.randint(0, 2))
        user = random.choice(usernames)
        pid = random.randint(10000, 99999)
        port = random.randint(40000, 65535)
        logs.append(
            f"{_fmt(ts)} sshd[{pid}]: "
            f"Failed password for {user} from {attacker_ip} port {port} ssh2"
        )

    # Successful login after brute force
    success_time = brute_start + timedelta(minutes=3, seconds=12)
    logs.append(
        f"{_fmt(success_time)} sshd[54321]: "
        f"Accepted password for {target_user} from {attacker_ip} port 52341 ssh2"
    )

    # Immediate privilege escalation
    escalation_time = success_time + timedelta(seconds=12)
    logs.append(
        f"{_fmt(escalation_time)} sudo: "
        f"{target_user} : TTY=pts/0 ; PWD=/home/{target_user} ; "
        f"USER=root ; COMMAND=/bin/bash"
    )

    # Suspicious file access
    access_time = escalation_time + timedelta(seconds=5)
    logs.append(
        f"{_fmt(access_time)} audit[1]: "
        f"USER_CMD pid=54322 uid=0 auid=1001 ses=42 "
        f"msg='op=access target=/etc/shadow res=success'"
    )

    # Data access
    data_time = access_time + timedelta(seconds=8)
    logs.append(
        f"{_fmt(data_time)} audit[1]: "
        f"USER_CMD pid=54323 uid=0 auid=1001 ses=42 "
        f"msg='op=access target=database_dump res=success'"
    )

    return logs


def generate_phishing_logs() -> list[str]:
    """Generate logs indicative of a phishing attack."""
    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    logs: list[str] = []

    # Normal email activity
    for i in range(3):
        ts = base_time + timedelta(seconds=i * 60)
        logs.append(f'{{"timestamp": "{_fmt(ts)}", "action": "email_received", "user": "employee{i+1}", "from": "colleague@company.com", "subject": "Meeting notes"}}')

    # Phishing email
    phish_time = base_time + timedelta(minutes=2)
    logs.append(f'{{"timestamp": "{_fmt(phish_time)}", "action": "email_received", "user": "jsmith", "from": "hr-update@c0mpany.com", "subject": "Urgent: Password Reset Required", "suspicious_url": "http://evil.example.com/login"}}')

    # User clicked the link
    click_time = phish_time + timedelta(minutes=1)
    logs.append(f'{{"timestamp": "{_fmt(click_time)}", "action": "url_click", "user": "jsmith", "url": "http://evil.example.com/login", "source": "email"}}')

    # Credentials submitted
    cred_time = click_time + timedelta(seconds=30)
    logs.append(f'{{"timestamp": "{_fmt(cred_time)}", "action": "credential_harvest", "user": "jsmith", "target": "http://evil.example.com/login", "method": "POST"}}')

    # Suspicious login from new location
    login_time = cred_time + timedelta(minutes=2)
    logs.append(f'{{"timestamp": "{_fmt(login_time)}", "action": "login_success", "user": "jsmith", "source_ip": "203.0.113.42", "location": "Unknown - Eastern Europe", "mfa_bypassed": true}}')

    return logs


def generate_data_exfiltration_logs() -> list[str]:
    """Generate logs indicative of data exfiltration."""
    base_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    logs: list[str] = []

    # Normal database queries
    for i in range(5):
        ts = base_time + timedelta(seconds=i * 120)
        logs.append(f'{{"timestamp": "{_fmt(ts)}", "action": "db_query", "user": "app_service", "query_type": "SELECT", "rows_returned": {random.randint(1, 100)}, "source_ip": "10.0.1.5"}}')

    # Suspicious bulk query
    bulk_time = base_time + timedelta(minutes=8)
    logs.append(f'{{"timestamp": "{_fmt(bulk_time)}", "action": "db_query", "user": "jdoe", "query_type": "SELECT *", "table": "customers", "rows_returned": 2345678, "source_ip": "192.168.1.105"}}')

    # Large data transfer
    transfer_time = bulk_time + timedelta(minutes=1)
    logs.append(f'{{"timestamp": "{_fmt(transfer_time)}", "action": "large_transfer", "user": "jdoe", "destination": "external-storage.example.com", "size_mb": 1250, "protocol": "HTTPS", "source_ip": "192.168.1.105"}}')

    # DNS exfiltration attempt
    dns_time = transfer_time + timedelta(seconds=30)
    logs.append(f'{{"timestamp": "{_fmt(dns_time)}", "action": "dns_query", "user": "jdoe", "query": "exfiltration.evil.example.com", "query_length": 253, "source_ip": "192.168.1.105"}}')

    return logs


def _fmt(dt: datetime) -> str:
    """Format a datetime for syslog style."""
    return dt.strftime("%b %d %H:%M:%S")
