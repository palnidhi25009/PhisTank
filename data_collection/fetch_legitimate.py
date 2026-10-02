"""
fetch_legitimate.py
--------------------
Downloads a list of legitimate/benign domains from the Tranco top
sites list (a research-grade, manipulation-resistant alternative to
the deprecated Alexa Top 1M — see https://tranco-list.eu).

Tranco publishes a new list ID daily; this script fetches the latest
one automatically.

Run this on a machine with normal internet access.

Usage:
    python fetch_legitimate.py --out ../data/legitimate_urls.csv --limit 5000
"""

import argparse
import csv
import io
import random
import sys
import zipfile
import requests

TRANCO_LATEST_CSV_URL = "https://tranco-list.eu/top-1m.csv.zip"

HEADERS = {"User-Agent": "phishing-research-project/1.0"}

# Realistic subdomains real legitimate sites actually use. Note that
# some of these ("login", "secure", "account") overlap with words in
# lexical_features.py's SUSPICIOUS_WORDS list — that's intentional.
# Real legitimate sites genuinely use login.microsoftonline.com,
# secure.bankofamerica.com, accounts.google.com, etc. If the training
# set never includes any legitimate example with these words, the
# model effectively learns "these words always mean phishing," which
# is false and causes real false positives (e.g. flagging
# mail.google.com or accounts.google.com).
COMMON_SUBDOMAINS = [
    "www", "mail", "shop", "blog", "support", "help", "docs", "app",
    "m", "login", "account", "accounts", "secure", "id", "my", "portal",
]

# Realistic paths, again deliberately including words that overlap with
# the suspicious-keyword feature list, for the same reason as above.
COMMON_PATHS = [
    "", "", "", "/about", "/products", "/search?q=example",
    "/help/contact", "/blog/2024/update", "/account/settings",
    "/login", "/account", "/secure/dashboard", "/user/profile",
    "/pricing", "/docs/api", "/support/faq",
]


def fetch_tranco_domains(limit: int = 5000) -> list:
    """
    Downloads the Tranco top-1M list (zipped CSV: rank,domain) and
    returns the top `limit` bare domains.
    """
    print("Fetching Tranco top sites list...")
    resp = requests.get(TRANCO_LATEST_CSV_URL, headers=HEADERS, timeout=60)
    resp.raise_for_status()

    domains = []
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        csv_name = zf.namelist()[0]
        with zf.open(csv_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            for row in reader:
                if len(row) >= 2:
                    domains.append(row[1].strip())
                if len(domains) >= limit:
                    break

    print(f"  Got {len(domains)} domains from Tranco.")
    return domains


def build_realistic_urls(domains: list, variants_per_domain: int = 3, seed: int = 42) -> list:
    """
    Turn bare domains into a realistic MIX of URL shapes: some with no
    subdomain, most with common subdomains (www, mail, login, etc.),
    and a range of realistic paths/query strings.

    This diversity matters a lot for training: if every legitimate
    example is just "https://domain.com" with nothing else, the model
    learns spurious rules like "any subdomain = phishing" or "the word
    'login' anywhere = phishing," neither of which is true in the real
    world. Real legitimate sites use subdomains and these words
    constantly (mail.google.com, login.microsoftonline.com, etc.).
    """
    rng = random.Random(seed)
    urls = []

    for domain in domains:
        for _ in range(variants_per_domain):
            # ~20% bare domain, ~80% with a subdomain (roughly matches
            # how often real-world traffic actually hits a subdomain)
            if rng.random() < 0.2:
                host = domain
            else:
                sub = rng.choice(COMMON_SUBDOMAINS)
                host = f"{sub}.{domain}"

            path = rng.choice(COMMON_PATHS)
            urls.append(f"https://{host}{path}")

    return urls


def main():
    parser = argparse.ArgumentParser(description="Collect legitimate domains from Tranco top sites.")
    parser.add_argument("--out", default="../data/legitimate_urls.csv", help="Output CSV path")
    parser.add_argument("--limit", type=int, default=5000, help="Number of top domains to fetch")
    # Skew sampling: real-world traffic is heavily skewed toward the top
    # of the list, but a phishing classifier benefits from also seeing
    # less "obviously huge" legitimate sites (small businesses, blogs,
    # regional sites). --skip lets you sample further down the ranking.
    parser.add_argument("--skip", type=int, default=0, help="Skip the first N domains before collecting")
    parser.add_argument("--variants-per-domain", type=int, default=3,
                         help="How many URL variants (different subdomains/paths) to generate per domain")
    args = parser.parse_args()

    try:
        domains = fetch_tranco_domains(limit=args.limit + args.skip)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Tranco fetch failed ({e}).", file=sys.stderr)
        sys.exit(1)

    domains = domains[args.skip:args.skip + args.limit]
    urls = build_realistic_urls(domains, variants_per_domain=args.variants_per_domain)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url in urls:
            writer.writerow([url, "legitimate"])

    print(f"\nSaved {len(urls)} legitimate URLs ({len(domains)} domains x "
          f"{args.variants_per_domain} variants) to {args.out}")


if __name__ == "__main__":
    main()
