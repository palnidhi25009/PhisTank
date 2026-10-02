"""
lexical_features.py
--------------------
Extracts lexical / URL-string features from a raw URL.
These features require NO network access — they operate purely on the
URL string itself, which makes them fast, safe, and always available
(even if the site is offline, geo-blocked, or takes too long to load).

Usage:
    from lexical_features import extract_lexical_features
    feats = extract_lexical_features("http://secure-paypal-login.tk/verify")
"""

import re
import math
from urllib.parse import urlparse

try:
    import tldextract
    # Disable live fetching of the public suffix list — use the bundled
    # snapshot instead. This avoids network calls/warnings and keeps
    # feature extraction fast and deterministic.
    _tld_extractor = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:  # pragma: no cover
    tldextract = None
    _tld_extractor = None

# Common URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rebrand.ly", "tiny.cc", "s.id",
}

# Suspicious keywords commonly used in phishing URLs to build false trust
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "banking",
    "signin", "webscr", "password", "billing", "suspend", "urgent",
    "authenticate", "wallet", "recover", "unlock", "invoice",
]

# High-risk free / disposable TLDs frequently abused by phishing campaigns
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "loan"}


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — random-looking domains score higher."""
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def _is_ip_address(host: str) -> bool:
    """True if the host is a raw IPv4 address instead of a domain name."""
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(ipv4_pattern, host or ""))


def extract_lexical_features(url: str) -> dict:
    """
    Extract a dictionary of numeric/boolean lexical features from a URL.

    Returns a flat dict suitable for direct use as a pandas row / ML feature vector.
    """
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0]  # strip port if present
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    # Domain parsing (registered domain, subdomain, suffix)
    if _tld_extractor:
        ext = _tld_extractor(url)
        subdomain = ext.subdomain
        domain = ext.domain
        suffix = ext.suffix
    else:
        subdomain, domain, suffix = "", host, ""

    features = {}

    # --- Basic length features ---
    features["url_length"] = len(url)
    features["host_length"] = len(host)
    features["path_length"] = len(path)

    # --- Structural / character-count features ---
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["num_question_marks"] = url.count("?")
    features["num_equals"] = url.count("=")
    features["num_at_symbols"] = url.count("@")
    features["num_ampersands"] = url.count("&")
    features["num_percent"] = url.count("%")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["digit_ratio"] = features["num_digits"] / len(url) if url else 0

    # --- Protocol / trust signals ---
    features["uses_https"] = int(parsed.scheme == "https")
    features["has_port"] = int(":" in parsed.netloc and not parsed.netloc.endswith(":"))

    # --- Suspicious structural patterns ---
    features["has_ip_address"] = int(_is_ip_address(host))
    features["has_at_symbol"] = int("@" in url)  # e.g. real.com@evil.com trick
    features["has_double_slash_redirect"] = int(url.rfind("//") > 7)  # // after protocol
    features["is_shortened"] = int(host in SHORTENER_DOMAINS)

    # --- Subdomain analysis (excessive subdomains are a red flag) ---
    subdomain_parts = [p for p in subdomain.split(".") if p]
    features["num_subdomains"] = len(subdomain_parts)
    features["has_excessive_subdomains"] = int(len(subdomain_parts) >= 3)

    # --- TLD risk ---
    features["suspicious_tld"] = int(suffix.split(".")[-1] in SUSPICIOUS_TLDS if suffix else 0)

    # --- Keyword-based signals ---
    features["num_suspicious_words"] = sum(1 for w in SUSPICIOUS_WORDS if w in full)
    features["has_suspicious_word"] = int(features["num_suspicious_words"] > 0)

    # Brand-in-subdomain trick, e.g. "paypal.com.verify-secure.tk"
    known_brands = ["paypal", "apple", "microsoft", "google", "amazon", "netflix",
                     "bank", "chase", "wellsfargo", "facebook", "instagram"]
    features["brand_in_subdomain_or_path"] = int(
        any(b in (subdomain + path).lower() for b in known_brands)
        and not any(b in domain.lower() for b in known_brands)
    )

    # --- Entropy (randomness) of domain — phishing domains often look random ---
    features["domain_entropy"] = round(_shannon_entropy(domain), 3)

    # --- Length-based heuristics used in classic phishing research ---
    features["long_url"] = int(len(url) > 75)          # UCI dataset threshold
    features["long_hostname"] = int(len(host) > 25)

    # --- Query string signals ---
    features["has_query_string"] = int(bool(query))
    features["query_length"] = len(query)

    return features


if __name__ == "__main__":
    # Quick self-test with a mix of legit-looking and phishing-looking URLs
    test_urls = [
        "https://www.google.com/search?q=phishing+detection",
        "http://secure-paypal-login-verify.tk/account/update",
        "http://192.168.1.5/wp-login.php",
        "https://accounts.google.com.signin-verify.xyz/oauth",
        "http://bit.ly/3xAbcde",
        "https://www.amazon.com/gp/css/order-history",
    ]
    import json
    for u in test_urls:
        print(f"\nURL: {u}")
        print(json.dumps(extract_lexical_features(u), indent=2))
