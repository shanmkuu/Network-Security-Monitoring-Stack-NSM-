#!/usr/bin/env python3
"""
NSM Traffic Generator
=====================
Simulates suspicious network activity on the nsm-net Docker network so that
Zeek has interesting events to log and the Kibana dashboards have data to show.

Patterns generated:
  1. TCP SYN port scan     — triggers Zeek's Scan::Port_Scan notice
  2. Cleartext HTTP login  — POST /login with credentials in plain HTTP
  3. DNS enumeration       — rapid subdomain lookups
  4. SSH brute-force hint  — rapid TCP connects to port 22
  5. Large data transfer   — bulk HTTP GET to pad byte totals

Run continuously with configurable SCAN_INTERVAL (seconds).
"""

import os
import time
import socket
import random
import logging
import threading
import subprocess
from datetime import datetime

import requests
import dns.resolver

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("traffic-gen")

# ── Config from env ──────────────────────────────────────────────────────────
TARGET_HOST   = os.environ.get("TARGET_HOST", "172.28.0.1")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "60"))
INTERNAL_HTTP = os.environ.get("INTERNAL_HTTP", f"http://{TARGET_HOST}")

# Common fake subdomains for DNS enum simulation
DNS_SUBDOMAINS = [
    "admin", "api", "mail", "vpn", "remote", "ftp", "smtp", "pop3",
    "imap", "portal", "dev", "staging", "beta", "internal", "corp",
    "jira", "confluence", "gitlab", "jenkins", "monitoring", "siem",
]

# Ports to scan
SCAN_PORTS = list(range(20, 1025))


# =============================================================================
# Attack Simulations
# =============================================================================

def simulate_port_scan(target: str) -> None:
    """
    TCP connect scan across common ports.
    Zeek will detect this via its Scan::Port_Scan policy and emit a notice.
    """
    log.info("▶ Starting port scan against %s", target)
    open_ports = []
    # Randomize ordering to look more realistic
    ports = random.sample(SCAN_PORTS, min(200, len(SCAN_PORTS)))
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                result = s.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
        except (socket.error, OSError):
            pass
        time.sleep(0.01)  # slight delay so Zeek can keep up
    log.info("✔ Port scan complete. Open ports found: %s", open_ports or "none")


def simulate_cleartext_http_login(target: str) -> None:
    """
    POST fake credentials to an HTTP endpoint.
    Zeek HTTP analyzer logs the POST body; Logstash flags it as cleartext_auth_attempt.
    We use httpbin.org as a public echo target in case the local host has no HTTP server.
    """
    log.info("▶ Simulating cleartext HTTP login attempt")
    fake_creds = [
        {"username": "admin", "password": "admin123"},
        {"username": "root", "password": "toor"},
        {"username": "test", "password": "password"},
        {"username": "administrator", "password": "P@ssw0rd"},
    ]
    targets = [
        "http://httpbin.org/post",               # public echo (if internet accessible)
        f"http://{target}/login",                # internal attempt
        f"http://{target}/auth/signin",
        f"http://{target}/api/v1/authenticate",
    ]
    for url in targets:
        cred = random.choice(fake_creds)
        try:
            resp = requests.post(
                url,
                data=cred,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                timeout=3,
            )
            log.info("  POST %s → %s", url, resp.status_code)
        except requests.RequestException as exc:
            log.debug("  POST %s failed (expected): %s", url, exc)
        time.sleep(0.5)


def simulate_dns_enumeration(base_domain: str = "example.internal") -> None:
    """
    Rapid DNS lookups for subdomains — triggers high DNS query rates in Zeek DNS logs.
    """
    log.info("▶ Starting DNS enumeration against %s", base_domain)
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 1
    resolver.lifetime = 1
    for sub in DNS_SUBDOMAINS:
        fqdn = f"{sub}.{base_domain}"
        try:
            resolver.resolve(fqdn, "A")
            log.debug("  ✔ %s resolved", fqdn)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            log.debug("  ✗ %s NX", fqdn)
        time.sleep(0.05)
    log.info("✔ DNS enumeration complete")


def simulate_ssh_brute_force(target: str) -> None:
    """
    Rapid TCP connects to port 22.
    Zeek SSH analyzer logs each connection attempt.
    """
    log.info("▶ Simulating SSH brute-force pattern against %s:22", target)
    usernames = ["root", "admin", "ubuntu", "ec2-user", "pi", "oracle", "postgres"]
    for username in usernames:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect_ex((target, 22))
                # Just connect; the real SSH handshake would fail — that's fine
        except (socket.error, OSError):
            pass
        log.debug("  SSH attempt as user: %s", username)
        time.sleep(0.2)
    log.info("✔ SSH bruteforce simulation complete")


def simulate_large_transfer(target: str) -> None:
    """
    Large HTTP GET to pad 'bytes transferred' totals in the top talkers table.
    """
    log.info("▶ Simulating large data transfer from %s", target)
    urls = [
        "http://speedtest.tele2.net/1MB.zip",
        f"http://{target}/large-file",
        "http://httpbin.org/bytes/500000",
    ]
    for url in urls:
        try:
            with requests.get(url, stream=True, timeout=5) as r:
                total = 0
                for chunk in r.iter_content(chunk_size=8192):
                    total += len(chunk)
                    if total > 500_000:
                        break
            log.info("  Downloaded ~%d bytes from %s", total, url)
            break
        except requests.RequestException as exc:
            log.debug("  Transfer %s failed: %s", url, exc)


# =============================================================================
# Main Loop
# =============================================================================

def run_cycle(target: str) -> None:
    ts = datetime.utcnow().isoformat()
    log.info("═══════════════════════════════════════")
    log.info("Cycle start: %s | Target: %s", ts, target)
    log.info("═══════════════════════════════════════")

    threads = [
        threading.Thread(target=simulate_dns_enumeration, args=("corp.internal",), daemon=True),
        threading.Thread(target=simulate_cleartext_http_login, args=(target,), daemon=True),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Sequential (to avoid overwhelming the small stack)
    simulate_ssh_brute_force(target)
    simulate_port_scan(target)
    simulate_large_transfer(target)

    log.info("Cycle complete. Next cycle in %ds", SCAN_INTERVAL)


def main() -> None:
    log.info("NSM Traffic Generator starting up")
    log.info("Target: %s  |  Interval: %ds", TARGET_HOST, SCAN_INTERVAL)

    # Initial delay to let other services stabilise
    log.info("Waiting 30s for stack to initialise…")
    time.sleep(30)

    while True:
        try:
            run_cycle(TARGET_HOST)
        except Exception as exc:  # pylint: disable=broad-except
            log.error("Cycle error (will retry): %s", exc)
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
