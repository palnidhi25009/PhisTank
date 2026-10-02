"""
content_features.py
--------------------
Extracts features from the actual HTML content of a page. Requires
fetching the URL, so it's the slowest and least safe feature category
(you're asking your server to visit a potentially malicious page).

SAFETY NOTE: Always fetch pages server-side (never in a user's browser),
with a short timeout, a size cap, and no automatic redirect to
executable content. This module uses `requests` with a strict timeout
and disables following excessive redirects.

Signal rationale:
- Phishing pages often load their real content/CSS/logo from the
  legitimate site's domain while collecting credentials on a fake one
  ("favicon from different domain", "external form action").
- Forms that POST to a different domain than the page itself are a
  massive red flag (credential exfiltration).
- Phishing kits often disable right-click / use pop-ups to prevent
  users from viewing page source.

Usage:
    from content_features import extract_content_features
    feats = extract_content_features("https://example.com")
"""

from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; PhishingDetectorBot/1.0; +research-project)"
}
MAX_CONTENT_BYTES = 2_000_000  # 2 MB cap so we don't download huge pages
REQUEST_TIMEOUT = 6  # seconds


def _same_domain(url_a: str, url_b: str) -> bool:
    try:
        return urlparse(url_a).netloc.lower() == urlparse(url_b).netloc.lower()
    except Exception:
        return False


def extract_content_features(url: str) -> dict:
    """
    Fetch the page and extract HTML/content-based features.
    Returns a dict with fetch_success=0 and sentinel values if the page
    could not be retrieved (offline, blocked, timeout, non-HTML, etc.)
    so this never crashes the overall pipeline.
    """
    features = {
        "fetch_success": 0,
        "num_links": -1,
        "num_external_links": -1,
        "num_forms": -1,
        "num_forms_external_action": -1,
        "has_password_field": -1,
        "favicon_external_domain": -1,
        "num_iframes": -1,
        "has_right_click_disabled": -1,
        "num_scripts": -1,
        "title_length": -1,
        "has_meta_refresh": -1,
    }

    try:
        resp = requests.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            allow_redirects=True,
        )
        # Enforce a size cap while streaming to avoid huge downloads
        content = b""
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > MAX_CONTENT_BYTES:
                break

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "<html" not in content[:500].decode("utf-8", "ignore").lower():
            return features  # not an HTML page, bail out gracefully

        soup = BeautifulSoup(content, "html.parser")
        features["fetch_success"] = 1

        final_url = resp.url  # after redirects

        # --- Links ---
        links = soup.find_all("a", href=True)
        features["num_links"] = len(links)
        features["num_external_links"] = sum(
            1 for a in links if a["href"].startswith("http") and not _same_domain(a["href"], final_url)
        )

        # --- Forms (credential harvesting signal) ---
        forms = soup.find_all("form")
        features["num_forms"] = len(forms)
        ext_action_forms = 0
        for f in forms:
            action = f.get("action", "")
            if action.startswith("http") and not _same_domain(action, final_url):
                ext_action_forms += 1
        features["num_forms_external_action"] = ext_action_forms
        features["has_password_field"] = int(bool(soup.find("input", {"type": "password"})))

        # --- Favicon domain mismatch ---
        icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if icon_link and icon_link.get("href", "").startswith("http"):
            features["favicon_external_domain"] = int(not _same_domain(icon_link["href"], final_url))
        else:
            features["favicon_external_domain"] = 0  # relative favicon = same domain, normal

        # --- iframes (often used to overlay fake content) ---
        features["num_iframes"] = len(soup.find_all("iframe"))

        # --- Right-click / context-menu disabling (common phishing-kit trick) ---
        page_text = str(soup).lower()
        features["has_right_click_disabled"] = int(
            "oncontextmenu" in page_text or "event.button==2" in page_text
        )

        # --- Script count (heavier obfuscation = more scripts, weak signal alone) ---
        features["num_scripts"] = len(soup.find_all("script"))

        # --- Title length (phishing pages sometimes have blank/generic titles) ---
        title_tag = soup.find("title")
        features["title_length"] = len(title_tag.get_text().strip()) if title_tag else 0

        # --- Meta-refresh redirect (used to bounce through pages) ---
        meta_refresh = soup.find("meta", attrs={"http-equiv": lambda x: x and x.lower() == "refresh"})
        features["has_meta_refresh"] = int(meta_refresh is not None)

    except requests.exceptions.RequestException:
        # Network error, timeout, DNS failure, SSL error, etc.
        # Leave sentinel -1 values; fetch_success stays 0.
        pass
    except Exception:
        # Any parsing error — fail closed rather than crash the pipeline
        pass

    return features


if __name__ == "__main__":
    import json
    # NOTE: requires live network access to actually fetch pages.
    test_urls = ["https://www.wikipedia.org"]
    for u in test_urls:
        print(f"\nURL: {u}")
        try:
            print(json.dumps(extract_content_features(u), indent=2))
        except Exception as e:
            print(f"  (fetch failed in this environment: {e})")
