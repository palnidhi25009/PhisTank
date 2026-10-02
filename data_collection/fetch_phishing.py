"""
fetch_phishing.py
------------------
Downloads current phishing URL feeds from public threat-intel sources.

Sources:
  - OpenPhish (free feed, no signup required, updated ~hourly)
    https://openphish.com/feed.txt
  - PhishTank (requires free API key for the bulk JSON dump, or you can
    use the public "online valid" CSV without a key)
    https://data.phishtank.com/data/online-valid.csv   (no key needed)
    https://data.phishtank.com/data/<API_KEY>/online-valid.json  (with key)

Run this on a machine with normal internet access — these domains are
not reachable from network-restricted sandboxes.

Usage:
    python fetch_phishing.py --out ../data/phishing_urls.csv --limit 5000
"""

import argparse
import csv
import sys
import time
import requests

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
PHISHTANK_CSV_URL = "https://data.phishtank.com/data/online-valid.csv"

HEADERS = {"User-Agent": "phishing-research-project/1.0"}


def fetch_openphish(limit: int = None) -> list:
    """OpenPhish free feed: plain text, one URL per line."""
    print("Fetching OpenPhish feed...")
    resp = requests.get(OPENPHISH_FEED_URL, headers=HEADERS, timeout=20)
    resp.raise_for_status()
    urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
    print(f"  Got {len(urls)} URLs from OpenPhish.")
    return urls[:limit] if limit else urls


def fetch_phishtank(limit: int = None) -> list:
    """
    PhishTank public CSV of currently-online verified phishing URLs.
    No API key required for this endpoint, but it's rate-limited —
    don't hammer it (their ToS asks for reasonable request frequency).
    """
    print("Fetching PhishTank feed...")
    resp = requests.get(PHISHTANK_CSV_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    lines = resp.text.splitlines()
    reader = csv.DictReader(lines)
    urls = [row["url"] for row in reader if row.get("url")]
    print(f"  Got {len(urls)} URLs from PhishTank.")
    return urls[:limit] if limit else urls


def main():
    parser = argparse.ArgumentParser(description="Collect phishing URLs from public feeds.")
    parser.add_argument("--out", default="../data/phishing_urls.csv", help="Output CSV path")
    parser.add_argument("--limit", type=int, default=None, help="Max URLs per source")
    parser.add_argument("--sources", nargs="+", default=["openphish", "phishtank"],
                         choices=["openphish", "phishtank"])
    args = parser.parse_args()

    all_urls = set()

    if "openphish" in args.sources:
        try:
            all_urls.update(fetch_openphish(args.limit))
        except requests.exceptions.RequestException as e:
            print(f"  WARNING: OpenPhish fetch failed ({e}). Skipping.", file=sys.stderr)

    if "phishtank" in args.sources:
        try:
            all_urls.update(fetch_phishtank(args.limit))
            time.sleep(1)  # be polite to the shared free endpoint
        except requests.exceptions.RequestException as e:
            print(f"  WARNING: PhishTank fetch failed ({e}). Skipping.", file=sys.stderr)

    if not all_urls:
        print("No URLs collected from any source. Check your network connection.", file=sys.stderr)
        sys.exit(1)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url in sorted(all_urls):
            writer.writerow([url, "phishing"])

    print(f"\nSaved {len(all_urls)} unique phishing URLs to {args.out}")


if __name__ == "__main__":
    main()
