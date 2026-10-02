"""
domain_monitor.py
------------------
Detects domain-level compromise (DNS hijacking, unauthorized TLS
certificates, registrar/nameserver takeover) — a fundamentally
different threat from the URL-classifier in features/. That model
answers "does this URL's TEXT look like a phishing URL?" This module
answers "has a domain I've verified before quietly started pointing
somewhere different?"

This matters because a hijacked domain doesn't change its URL at all —
victims still type/see the real domain name. Lexical/URL features are
blind to this by design; only comparing a domain's *current* state
against a trusted *baseline* can catch it.

What it tracks per domain:
  - Resolved IP address(es)               (DNS)
  - Hosting organization / ASN            (IP reputation lookup)
  - TLS certificate fingerprint + issuer  (direct TLS handshake)
  - Registrar + nameservers               (WHOIS)

Usage:
    # Record what "normal" looks like for a domain you trust/control
    python domain_monitor.py baseline --domain example.com

    # Later (e.g. via cron), check for drift from that baseline
    python domain_monitor.py check --domain example.com

    # Check every domain that has a saved baseline
    python domain_monitor.py check --all

NOTE: needs live network access (DNS, HTTPS, WHOIS) — run on a machine
with normal internet access, not a sandboxed/offline environment.
"""

import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
from datetime import datetime, timezone

import requests

try:
    import whois  # python-whois
except ImportError:
    whois = None

BASELINE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baselines")
IP_ORG_LOOKUP_URL = "http://ip-api.com/json/{ip}?fields=status,message,org,isp,as,country,countryCode"
REQUEST_TIMEOUT = 6


# --------------------------------------------------------------------
# Data collection — each function fails gracefully (returns partial
# data + an "error" key) rather than crashing the whole check, since
# any one of DNS/TLS/WHOIS/IP-lookup can independently be unreachable,
# rate-limited, or blocked by a firewall.
# --------------------------------------------------------------------

def resolve_ips(domain: str) -> dict:
    """Resolve all IPv4 addresses a domain currently points to."""
    try:
        socket.setdefaulttimeout(REQUEST_TIMEOUT)
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = sorted({info[4][0] for info in infos})
        return {"ip_addresses": ips, "error": None}
    except (socket.gaierror, socket.timeout, UnicodeError) as e:
        return {"ip_addresses": [], "error": str(e)}


def get_ip_org(ip: str) -> dict:
    """Look up the hosting organization/ASN/country for an IP address."""
    if not ip:
        return {"org": None, "isp": None, "asn": None, "country": None, "error": "no ip"}
    try:
        resp = requests.get(IP_ORG_LOOKUP_URL.format(ip=ip), timeout=REQUEST_TIMEOUT)
        data = resp.json()
        if data.get("status") != "success":
            return {"org": None, "isp": None, "asn": None, "country": None,
                     "error": data.get("message", "lookup failed")}
        return {
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("as"),
            "country": data.get("countryCode"),
            "error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"org": None, "isp": None, "asn": None, "country": None, "error": str(e)}


def get_cert_info(domain: str, port: int = 443) -> dict:
    """
    Connect directly over TLS and extract the certificate's fingerprint,
    issuer, and validity window. This is a real handshake, not an HTTP
    request — it works even if the site returns non-HTML content.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()

        fingerprint = hashlib.sha256(der_cert).hexdigest()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "fingerprint_sha256": fingerprint,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject_cn": subject.get("commonName"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "error": None,
        }
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError) as e:
        return {
            "fingerprint_sha256": None, "issuer": None, "subject_cn": None,
            "not_before": None, "not_after": None, "error": str(e),
        }


def get_whois_info(domain: str) -> dict:
    """Registrar + nameservers — a hijack via registrar-account takeover shows up here."""
    if whois is None:
        return {"registrar": None, "nameservers": None, "updated_date": None, "error": "python-whois not installed"}
    try:
        w = whois.whois(domain)
        nameservers = w.name_servers
        if isinstance(nameservers, list):
            nameservers = sorted({ns.lower() for ns in nameservers if ns})
        updated = w.updated_date
        if isinstance(updated, list):
            updated = updated[0] if updated else None
        if isinstance(updated, datetime):
            updated = updated.isoformat()
        return {
            "registrar": w.registrar,
            "nameservers": nameservers,
            "updated_date": updated,
            "error": None,
        }
    except Exception as e:
        return {"registrar": None, "nameservers": None, "updated_date": None, "error": str(e)}


def collect_snapshot(domain: str) -> dict:
    """Gather everything we track for a domain into one snapshot dict."""
    dns_info = resolve_ips(domain)
    primary_ip = dns_info["ip_addresses"][0] if dns_info["ip_addresses"] else None

    snapshot = {
        "domain": domain,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "dns": dns_info,
        "ip_org": get_ip_org(primary_ip),
        "certificate": get_cert_info(domain),
        "whois": get_whois_info(domain),
    }
    return snapshot


# --------------------------------------------------------------------
# Baseline storage
# --------------------------------------------------------------------

def baseline_path(domain: str) -> str:
    safe_name = domain.replace("/", "_").replace(":", "_")
    return os.path.join(BASELINE_DIR, f"{safe_name}.json")


def save_baseline(domain: str, snapshot: dict) -> str:
    os.makedirs(BASELINE_DIR, exist_ok=True)
    path = baseline_path(domain)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)
    return path


def load_baseline(domain: str) -> dict:
    path = baseline_path(domain)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def list_baselined_domains() -> list:
    if not os.path.isdir(BASELINE_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(BASELINE_DIR) if f.endswith(".json"))


# --------------------------------------------------------------------
# Comparison / alerting
# --------------------------------------------------------------------

def compare_snapshots(baseline: dict, current: dict) -> list:
    """
    Compare a saved baseline against a fresh snapshot. Returns a list
    of alert dicts: {severity, category, message}.

    Severity guide:
      INFO     - a change that happens routinely and isn't inherently
                 suspicious on its own (e.g. certificate renewal by the
                 SAME issuer)
      WARNING  - a change that's sometimes legitimate (site migration,
                 CDN change) but worth a human glancing at
      CRITICAL - a combination or type of change that's rarely
                 legitimate and matches known hijack patterns
    """
    alerts = []

    base_ips = set(baseline.get("dns", {}).get("ip_addresses", []))
    curr_ips = set(current.get("dns", {}).get("ip_addresses", []))
    ip_changed = base_ips and curr_ips and base_ips != curr_ips

    base_org = baseline.get("ip_org", {}).get("org")
    curr_org = current.get("ip_org", {}).get("org")
    org_changed = base_org and curr_org and base_org != curr_org

    base_fp = baseline.get("certificate", {}).get("fingerprint_sha256")
    curr_fp = current.get("certificate", {}).get("fingerprint_sha256")
    cert_changed = base_fp and curr_fp and base_fp != curr_fp

    base_issuer = baseline.get("certificate", {}).get("issuer")
    curr_issuer = current.get("certificate", {}).get("issuer")
    issuer_changed = base_issuer and curr_issuer and base_issuer != curr_issuer

    base_registrar = baseline.get("whois", {}).get("registrar")
    curr_registrar = current.get("whois", {}).get("registrar")
    registrar_changed = base_registrar and curr_registrar and base_registrar != curr_registrar

    base_ns = set(baseline.get("whois", {}).get("nameservers") or [])
    curr_ns = set(current.get("whois", {}).get("nameservers") or [])
    ns_changed = base_ns and curr_ns and base_ns != curr_ns

    # --- Individual signals ---
    if ip_changed:
        alerts.append({
            "severity": "WARNING",
            "category": "ip_change",
            "message": f"IP address changed: {sorted(base_ips)} -> {sorted(curr_ips)}",
        })

    if org_changed:
        alerts.append({
            "severity": "WARNING",
            "category": "hosting_org_change",
            "message": f"Hosting organization changed: '{base_org}' -> '{curr_org}'",
        })

    if cert_changed and not issuer_changed:
        alerts.append({
            "severity": "INFO",
            "category": "cert_renewed",
            "message": "TLS certificate fingerprint changed but issuer is the same "
                       "(likely a routine renewal, not necessarily suspicious).",
        })

    if issuer_changed:
        alerts.append({
            "severity": "WARNING",
            "category": "cert_issuer_change",
            "message": f"TLS certificate issuer changed: '{base_issuer}' -> '{curr_issuer}'",
        })

    if registrar_changed:
        alerts.append({
            "severity": "WARNING",
            "category": "registrar_change",
            "message": f"Registrar changed: '{base_registrar}' -> '{curr_registrar}'",
        })

    if ns_changed:
        alerts.append({
            "severity": "WARNING",
            "category": "nameserver_change",
            "message": f"Nameservers changed: {sorted(base_ns)} -> {sorted(curr_ns)}",
        })

    # --- Combined signals — these combinations are the classic hijack fingerprint ---
    if ip_changed and issuer_changed:
        alerts.append({
            "severity": "CRITICAL",
            "category": "combined_ip_and_cert",
            "message": "IP address AND certificate issuer changed together. This is the "
                       "signature of a domain-level compromise (DNS hijack or registrar "
                       "takeover), not a routine hosting change — investigate immediately.",
        })

    if ns_changed and ip_changed:
        alerts.append({
            "severity": "CRITICAL",
            "category": "combined_ns_and_ip",
            "message": "Nameservers AND IP address changed together. If you didn't "
                       "initiate a migration, treat this as a likely account/DNS "
                       "takeover and verify registrar access immediately.",
        })

    return alerts


# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------

def cmd_baseline(domain: str):
    print(f"Collecting baseline snapshot for {domain}...")
    snapshot = collect_snapshot(domain)
    path = save_baseline(domain, snapshot)

    print(f"\nSaved baseline to {path}")
    print(f"  IP addresses : {snapshot['dns']['ip_addresses'] or '(lookup failed)'}")
    print(f"  Hosting org  : {snapshot['ip_org']['org'] or '(lookup failed)'}")
    print(f"  TLS issuer   : {snapshot['certificate']['issuer'] or '(lookup failed)'}")
    print(f"  Registrar    : {snapshot['whois']['registrar'] or '(lookup failed)'}")

    any_failed = any(
        snapshot[section].get("error")
        for section in ("dns", "ip_org", "certificate", "whois")
    )
    if any_failed:
        print("\n  NOTE: one or more lookups failed (see above) — this is common for "
              "WHOIS in particular, which is often rate-limited. Re-run later if a "
              "field you care about is missing.")


def cmd_check(domain: str):
    baseline = load_baseline(domain)
    if baseline is None:
        print(f"No baseline found for {domain}. Run:\n  python domain_monitor.py baseline --domain {domain}")
        return

    print(f"Checking {domain} against baseline from {baseline['checked_at']}...")
    current = collect_snapshot(domain)
    alerts = compare_snapshots(baseline, current)

    if not alerts:
        print(f"\n  No changes detected. {domain} matches its baseline.")
        return

    severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 3))

    print(f"\n  {len(alerts)} change(s) detected:\n")
    for a in alerts:
        print(f"  [{a['severity']}] {a['category']}: {a['message']}")

    if any(a["severity"] == "CRITICAL" for a in alerts):
        print(f"\n  >>> CRITICAL alert(s) present for {domain}. Recommend manual verification. <<<")


def main():
    parser = argparse.ArgumentParser(description="Monitor a domain for signs of hijacking/compromise.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_baseline = sub.add_parser("baseline", help="Record the current state of a domain as its trusted baseline")
    p_baseline.add_argument("--domain", required=True)

    p_check = sub.add_parser("check", help="Compare a domain's current state against its saved baseline")
    p_check.add_argument("--domain", help="Check a single domain")
    p_check.add_argument("--all", action="store_true", help="Check every domain with a saved baseline")

    args = parser.parse_args()

    if args.command == "baseline":
        cmd_baseline(args.domain)
    elif args.command == "check":
        if args.all:
            domains = list_baselined_domains()
            if not domains:
                print("No baselines saved yet. Run `baseline --domain <domain>` first.")
                sys.exit(1)
            for d in domains:
                cmd_check(d)
                print()
        elif args.domain:
            cmd_check(args.domain)
        else:
            print("Specify --domain <domain> or --all", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
