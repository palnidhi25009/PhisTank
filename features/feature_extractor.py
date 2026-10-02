"""
feature_extractor.py
---------------------
Orchestrates all feature extraction modules into a single flat feature
vector per URL. This is the main entry point for turning a raw URL
into an ML-ready row.

Design choice: features are tiered by cost/reliability so you can
choose how much you're willing to pay per URL at inference time:

  Tier 1 - lexical only        : ~0ms,  always available, no network
  Tier 2 - lexical + domain    : ~1-3s, needs network (WHOIS/DNS)
  Tier 3 - lexical + domain +  : ~2-6s, needs network (fetches the page)
           content

For a real-time browser-extension use case, Tier 1 alone (or Tier 1+2
with caching) is usually the practical choice — Tier 3 is best suited
for offline dataset building or backend batch scoring.

Usage:
    from feature_extractor import extract_features

    feats = extract_features("http://example.com", tier=1)
    feats = extract_features("http://example.com", tier=3)  # full feature set
"""

from lexical_features import extract_lexical_features
from domain_features import extract_domain_features
from content_features import extract_content_features


def extract_features(url: str, tier: int = 1) -> dict:
    """
    Extract a full feature dict for a single URL.

    Args:
        url: the raw URL string.
        tier: 1 = lexical only, 2 = + domain/WHOIS, 3 = + page content.

    Returns:
        Flat dict of feature_name -> value, prefixed so downstream code
        can tell which tier a feature came from if needed.
    """
    features = {}
    features.update(extract_lexical_features(url))

    if tier >= 2:
        features.update(extract_domain_features(url))

    if tier >= 3:
        features.update(extract_content_features(url))

    return features


def extract_features_batch(urls: list, tier: int = 1, verbose: bool = True) -> list:
    """
    Extract features for a list of URLs. Returns a list of dicts, each
    with a 'url' key added for traceability. Failures on individual
    URLs are caught so one bad URL doesn't kill the whole batch.
    """
    results = []
    total = len(urls)
    for i, url in enumerate(urls, 1):
        if verbose and i % 50 == 0:
            print(f"  Processed {i}/{total} URLs...")
        try:
            feats = extract_features(url, tier=tier)
            feats["url"] = url
            feats["extraction_error"] = 0
        except Exception as e:
            feats = {"url": url, "extraction_error": 1, "error_message": str(e)}
        results.append(feats)
    return results


if __name__ == "__main__":
    import json
    sample = "http://secure-paypal-login-verify.tk/account/update"
    print("Tier 1 (lexical only):")
    print(json.dumps(extract_features(sample, tier=1), indent=2))
