"""
build_dataset.py
-----------------
Combines the phishing and legitimate URL CSVs, extracts features for
every URL, and writes a single ML-ready dataset (features + label).

This is the script you run after fetch_phishing.py and
fetch_legitimate.py have produced their raw URL lists.

Usage:
    python build_dataset.py \\
        --phishing ../data/phishing_urls.csv \\
        --legitimate ../data/legitimate_urls.csv \\
        --out ../data/dataset.csv \\
        --tier 1

Tier guidance (see features/feature_extractor.py for details):
    tier 1 -> fast, no network needed at inference time (recommended
              default for a first working model / real-time use case)
    tier 2 -> adds WHOIS/DNS lookups (slower, ~1-3s/URL, needs network)
    tier 3 -> adds page-content fetch (slowest, ~2-6s/URL, needs network,
              and means visiting live phishing URLs server-side)
"""

import argparse
import csv
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "features"))
from feature_extractor import extract_features  # noqa: E402


def load_urls(path: str) -> list:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append((row["url"], row["label"]))
    return rows


def process_single_url(item: tuple, tier: int) -> dict:
    url, label = item
    try:
        feats = extract_features(url, tier=tier)
        feats["url"] = url
        feats["label"] = label
        return feats
    except Exception as e:
        return {"url": url, "label": label, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Build labeled feature dataset from raw URL lists.")
    parser.add_argument("--phishing", required=True, help="CSV with phishing URLs (from fetch_phishing.py)")
    parser.add_argument("--legitimate", required=True, help="CSV with legitimate URLs (from fetch_legitimate.py)")
    parser.add_argument("--out", default="../data/dataset.csv", help="Output feature dataset CSV")
    parser.add_argument("--tier", type=int, default=1, choices=[1, 2, 3],
                         help="Feature tier: 1=lexical, 2=+domain/WHOIS, 3=+page content")
    parser.add_argument("--workers", type=int, default=32,
                         help="Number of parallel worker threads for tier 2/3 network lookups")
    args = parser.parse_args()

    phishing_rows = load_urls(args.phishing)
    legit_rows = load_urls(args.legitimate)
    all_rows = phishing_rows + legit_rows

    print(f"Loaded {len(phishing_rows)} phishing + {len(legit_rows)} legitimate = {len(all_rows)} total URLs")
    print(f"Extracting tier {args.tier} features for each URL using {args.workers} parallel workers...")

    written = 0
    start = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_single_url, item, args.tier): i for i, item in enumerate(all_rows, 1)}
        
        for future in as_completed(futures):
            res = future.result()
            if "error" not in res:
                results.append(res)
            written += 1
            if written % 500 == 0 or written == len(all_rows):
                elapsed = time.time() - start
                rate = written / elapsed if elapsed > 0 else 0
                print(f"  [{written}/{len(all_rows)}] processed ({elapsed:.1f}s elapsed, {rate:.1f} URLs/sec)")

    if not results:
        print("ERROR: No valid feature vectors were extracted.", file=sys.stderr)
        sys.exit(1)

    fieldnames = list(results[0].keys())
    with open(args.out, "w", newline="", encoding="utf-8") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    elapsed_total = time.time() - start
    print(f"\nDone. Saved {len(results)} rows to {args.out} in {elapsed_total:.1f} seconds!")


if __name__ == "__main__":
    main()

