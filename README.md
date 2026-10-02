# Phishing URL Detector — Data Collection & Feature Extraction

This is stage 1 of the phishing detection project: collecting labeled
URL data and turning raw URLs into ML-ready feature vectors. Model
training, evaluation, and deployment build on top of this.

## Project structure

```
phishing_detector/
├── data_collection/
│   ├── fetch_phishing.py      # Pulls phishing URLs from OpenPhish + PhishTank
│   ├── fetch_legitimate.py    # Pulls legitimate domains from Tranco top sites
│   └── build_dataset.py       # Combines both + extracts features -> dataset.csv
├── features/
│   ├── lexical_features.py    # URL-string features (no network needed)
│   ├── domain_features.py     # WHOIS/DNS features (needs network)
│   ├── content_features.py    # Page HTML features (needs network, fetches page)
│   └── feature_extractor.py   # Orchestrates all three into one feature vector
├── data/                      # Output CSVs land here
├── models/                    # (next stage) trained model artifacts
├── requirements.txt
└── README.md
```

## ⚠️ Important: network access required

`fetch_phishing.py`, `fetch_legitimate.py`, and any `tier >= 2` feature
extraction need real internet access to OpenPhish, PhishTank, Tranco,
WHOIS servers, and arbitrary websites. **Run these on your own machine**
— they will not work in network-restricted sandboxes.

## Quick start

```bash
pip install -r requirements.txt

cd data_collection

# 1. Collect raw labeled URLs
python fetch_phishing.py --out ../data/phishing_urls.csv --limit 3000
python fetch_legitimate.py --out ../data/legitimate_urls.csv --limit 3000

# 2. Extract features and build the final ML-ready dataset
python build_dataset.py \
    --phishing ../data/phishing_urls.csv \
    --legitimate ../data/legitimate_urls.csv \
    --out ../data/dataset.csv \
    --tier 1
```

This produces `data/dataset.csv` with one row per URL, ~30 numeric
feature columns, and a `label` column (`phishing` / `legitimate`) —
ready to load into scikit-learn / XGBoost for training.

## Feature tiers

| Tier | Includes | Speed | Needs network at inference time? |
|------|----------|-------|-----------------------------------|
| 1 | Lexical (URL string) only | ~instant | No |
| 2 | + WHOIS/DNS (domain age, registration length) | ~1–3s/URL | Yes |
| 3 | + Page content (forms, links, favicon, iframes) | ~2–6s/URL | Yes |

**Recommendation:** start with **Tier 1**. It's the only tier that's
practical for a real-time browser extension or API that needs a sub-
second response, and lexical features alone already capture most of
the classic phishing tells (IP-address hosts, suspicious TLDs, brand
names stuffed into subdomains, excessive hyphens/subdomains, etc.).
Add Tier 2/3 later as a slower "deep check" path, or to boost accuracy
in offline batch scoring where latency doesn't matter.

## Tier 1 lexical features (30 total)

Structural: `url_length`, `host_length`, `path_length`, counts of dots/
hyphens/underscores/slashes/digits, `digit_ratio`.

Trust signals: `uses_https`, `has_ip_address`, `has_at_symbol`,
`is_shortened`, `suspicious_tld`.

Subdomain abuse: `num_subdomains`, `has_excessive_subdomains`,
`brand_in_subdomain_or_path` (catches tricks like
`accounts.google.com.evil.xyz`).

Keyword signals: `num_suspicious_words`, `has_suspicious_word` (login,
verify, secure, confirm, etc.)

Randomness: `domain_entropy` (Shannon entropy — auto-generated phishing
domains tend to look more random than real brand names).

## Data sources

- **Phishing:** [OpenPhish](https://openphish.com) free feed (no signup),
  [PhishTank](https://phishtank.org) public CSV (no key needed for basic access)
- **Legitimate:** [Tranco](https://tranco-list.eu) top sites list — a
  more manipulation-resistant, research-grade replacement for the
  deprecated Alexa Top 1M

## A note on class balance and dataset freshness

- Aim for roughly balanced classes (similar counts of phishing vs.
  legitimate) — real-world phishing rates are much lower than 50%, but
  a balanced training set trains a better classifier; you can always
  adjust the decision threshold later based on your precision/recall
  needs.
- Phishing URLs on public feeds get taken down within hours, so
  `has_dns_record` / content-fetch features may fail for a meaningful
  chunk of them by the time you scrape — that's expected and is itself
  a real-world constraint worth mentioning in your writeup.
- Re-run the collection scripts periodically if you want a dataset
  that reflects current phishing patterns rather than a static snapshot.

## Next steps (not yet built)

1. **Model training** — load `dataset.csv`, split train/test, compare
   Logistic Regression / Random Forest / XGBoost, tune hyperparameters.
2. **Evaluation** — precision/recall/F1/ROC-AUC, confusion matrix,
   explicitly discuss the false-positive vs. false-negative tradeoff.
3. **Deployment** — Flask/FastAPI endpoint that runs Tier 1 features
   through the trained model for instant scoring, with Tier 2/3 as an
   optional slower "deep scan."

Ask for help with any of these when you're ready to move on.
