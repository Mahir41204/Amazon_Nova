"""
Custom attack simulator — sends realistic attack traffic.
Run while the server is running (normal or hybrid mode).

Each phase sends ALL logs as a single batch so the pipeline
can detect multi-line attack patterns (e.g. brute-force needs ≥5).
"""

import httpx
import time
import json
import sys

BASE_URL = "http://localhost:8000"
TIMEOUT = 120.0  # seconds — real Nova pipeline takes 15-30s per batch

client = httpx.Client(timeout=TIMEOUT)

# ── Step 1: Authenticate ──────────────────────────────────────────
print("🔑 Getting JWT token...")
r = client.post(f"{BASE_URL}/auth/token", json={
    "username": "admin",
    "password": "admin"
})
token = r.json()["access_token"]
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}
print(f"   ✅ Token obtained\n")


def send_attack_batch(phase_name: str, logs: list[str]):
    """Send all logs for a phase as a single batch and display results."""
    print("=" * 60)
    print(f"  🎯 {phase_name}")
    print("=" * 60)
    print(f"  📦 Sending {len(logs)} log lines as batch:")
    for i, log in enumerate(logs, 1):
        print(f"      [{i:02d}] {log[:65]}")

    print(f"\n  ⏳ Waiting for Nova pipeline (up to {int(TIMEOUT)}s)...")
    start = time.perf_counter()

    try:
        r = client.post(
            f"{BASE_URL}/analyze-log",
            headers=headers,
            json={"logs": logs},
        )
        elapsed = time.perf_counter() - start

        if r.status_code == 200:
            data = r.json()
            stages = data.get("stages", {})

            # Extract key results
            log_analysis = stages.get("log_analysis", {}).get("result", {})
            threat = stages.get("threat_classification", {}).get("result", {})
            impact = stages.get("impact_simulation", {}).get("result", {})
            response = stages.get("response", {}).get("result", {})

            print(f"  ✅ Completed in {elapsed:.1f}s")
            print(f"  ──────────────────────────────────────")
            print(f"  📊 Anomaly Score   : {log_analysis.get('anomaly_score', 'N/A')}")
            print(f"  🎯 Threat Type     : {threat.get('threat_type', 'N/A')}")
            print(f"  📈 Confidence      : {threat.get('confidence_score', 'N/A')}")
            print(f"  🛡  Risk Level      : {impact.get('risk_level', 'N/A')}")
            print(f"  💰 Financial Impact: {impact.get('estimated_financial_impact', 'N/A')}")
            print(f"  💥 Severity Score  : {impact.get('severity_score', 'N/A')}")
            print(f"  🔧 Action          : {threat.get('recommended_action', 'N/A')}")
            print(f"  👤 Decision        : {response.get('decision', 'N/A')}")
            print(f"  📝 Explanation     : {threat.get('explanation', 'N/A')[:100]}...")
        else:
            print(f"  ⚠️ HTTP {r.status_code}: {r.text[:200]}")

    except httpx.ReadTimeout:
        elapsed = time.perf_counter() - start
        print(f"  ❌ Timeout after {elapsed:.1f}s — pipeline too slow")

    print()
    time.sleep(2)  # Brief pause between phases


# ── Phase 1: SSH Brute-Force Attack ───────────────────────────────
send_attack_batch("PHASE 1: SSH Brute-Force Attack (7 failed logins)", [
    "sshd[1001]: Failed password for root from 10.99.88.77 port 22",
    "sshd[1002]: Failed password for admin from 10.99.88.77 port 22",
    "sshd[1003]: Invalid user guest from 10.99.88.77 port 22",
    "sshd[1004]: Failed password for ubuntu from 10.99.88.77 port 22",
    "sshd[1005]: Failed password for postgres from 10.99.88.77 port 22",
    "sshd[1006]: Failed password for root from 10.99.88.77 port 22",
    "sshd[1007]: Failed password for test from 10.99.88.77 port 22",
])

# ── Phase 2: Privilege Escalation Attempt ─────────────────────────
send_attack_batch("PHASE 2: Privilege Escalation Attempt", [
    "sudo: user1 : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
    "kernel: suspicious module loaded: rootkit.ko",
    "su[9999]: FAILED su for root by user1",
    "audit: user1 accessed /etc/shadow (DENIED)",
])

# ── Phase 3: Data Exfiltration Attempt ────────────────────────────
send_attack_batch("PHASE 3: Data Exfiltration Attempt", [
    "rsync[7777]: transfer /etc/passwd to 185.220.101.5",
    "rsync[7778]: uploading database_backup.sql.gz (2.1GB) to external",
    "iptables: outbound connection to known C2 server 198.51.100.23",
])

# ── Check Results ─────────────────────────────────────────────────
print("=" * 60)
print("  📊 CHECKING RESULTS")
print("=" * 60)

r = client.get(f"{BASE_URL}/health")
health = r.json()
print(f"  System Status : {health.get('status', 'unknown')}")

r = client.get(f"{BASE_URL}/realtime/status")
if r.status_code == 200:
    status = r.json()
    print(f"  Events Processed : {status.get('total_events_processed', 'N/A')}")
    print(f"  Nova Activations : {status.get('nova_activations', 'N/A')}")
    print(f"  Blocked IPs      : {status.get('blocked_ips', 'N/A')}")

r = client.get(f"{BASE_URL}/incidents", headers=headers)
if r.status_code == 200:
    incidents = r.json()
    print(f"  Total Incidents  : {len(incidents)}")
    for inc in incidents[-3:]:
        print(f"    - {inc.get('incident_id', '?')}: {inc.get('threat_type', '?')}")

print("\n" + "=" * 60)
print("  ✅ Attack simulation complete!")
print("=" * 60)

client.close()
