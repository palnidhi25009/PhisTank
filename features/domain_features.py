"""
domain_features.py
-------------------
Extracts domain-reputation features that require WHOIS/DNS lookups.
Features are cached per registered domain to prevent duplicate lookups, and
socket errors / timeouts are handled gracefully with sentinel -1 values.
"""

import socket
import urllib.request
import json
from datetime import datetime, timezone

try:
    import whois  # python-whois package
except ImportError:
    whois = None

try:
    import tldextract
    _tld = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    _tld = None


_DOMAIN_CACHE = {}


def _to_datetime(value):
    """WHOIS libraries sometimes return a list of dates instead of one."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value
    return None


def _get_registered_domain(host: str) -> str:
    """Extract registered domain (e.g. 'whatsapp.com' from 'web.whatsapp.com')."""
    if _tld:
        ext = _tld(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _check_dns(host: str, timeout: float = 2.0) -> int:
    """Fast DNS resolution check (socket getaddrinfo, fallback to Google DoH without API key)."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None)
        return 1
    except Exception:
        pass

    # Fallback: Google DNS-over-HTTPS (Free public API, no key needed)
    try:
        url = f"https://dns.google/resolve?name={host}&type=A"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("Status") == 0 and "Answer" in data:
                return 1
    except Exception:
        pass

    return 0


def extract_domain_features(domain_or_url: str, timeout: float = 3.0) -> dict:
    """
    Extract WHOIS/DNS-based features for a domain or URL.
    Results are cached per registered domain to avoid redundant lookups.
    """
    host = domain_or_url.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0].lower()

    registered_domain = _get_registered_domain(host)

    if registered_domain in _DOMAIN_CACHE:
        return _DOMAIN_CACHE[registered_domain].copy()

    features = {
        "domain_age_days": -1,
        "domain_registration_length_days": -1,
        "has_dns_record": 0,
        "has_valid_whois": 0,
        "days_until_expiration": -1,
    }

    # 1. Fast DNS Check
    features["has_dns_record"] = _check_dns(host, timeout=timeout)
    if features["has_dns_record"] == 0 and registered_domain != host:
        features["has_dns_record"] = _check_dns(registered_domain, timeout=timeout)

    # 2. WHOIS Lookup
    if whois is not None:
        try:
            w = whois.whois(registered_domain)
            creation = _to_datetime(w.creation_date)
            expiration = _to_datetime(w.expiration_date)
            now = datetime.now(timezone.utc)

            if creation:
                features["domain_age_days"] = max((now - creation).days, 0)
                features["has_valid_whois"] = 1

            if creation and expiration:
                features["domain_registration_length_days"] = (expiration - creation).days

            if expiration:
                features["days_until_expiration"] = (expiration - now).days

        except Exception:
            pass

    _DOMAIN_CACHE[registered_domain] = features
    return features.copy()


if __name__ == "__main__":
    import json
    test_domains = ["google.com", "web.whatsapp.com", "wikipedia.org"]
    for d in test_domains:
        print(f"\nDomain: {d}")
        print(json.dumps(extract_domain_features(d), indent=2))

