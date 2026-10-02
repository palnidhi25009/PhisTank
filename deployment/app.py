"""
app.py
------
Flask API + simple web UI for real-time phishing URL detection using
the model trained in models/train_model.py.

Loads (on startup, once):
  - models/best_model.joblib
  - models/scaler.joblib
  - models/feature_columns.json

Endpoints:
  GET  /                -> simple web form (paste a URL, get a verdict)
  POST /api/check        -> JSON API: {"url": "..."} -> verdict + confidence

Usage:
    cd deployment
    python app.py
    # then open http://127.0.0.1:5000 in your browser

Or call the API directly:
    curl -X POST http://127.0.0.1:5000/api/check \\
        -H "Content-Type: application/json" \\
        -d '{"url": "http://secure-paypal-login.tk/verify"}'
"""

import json
import os
import sys

import joblib
from flask import Flask, jsonify, render_template, request

from flask_cors import CORS

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "features"))
from feature_extractor import extract_features  # noqa: E402

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "..", "models")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

app = Flask(__name__, template_folder=TEMPLATE_DIR)


# CORS is required so the browser extension (running under a
# chrome-extension:// origin) can call this API from a different host
# than the one serving it. Wide open ("*") is fine for local/portfolio
# use; if you ever deploy this publicly, restrict it to your extension's
# specific ID instead, e.g. origins=["chrome-extension://<your-ext-id>"].
CORS(app)

# --- Load model artifacts once at startup, not per-request ---
MODEL_PATH = os.path.join(MODELS_DIR, "best_model.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
COLUMNS_PATH = os.path.join(MODELS_DIR, "feature_columns.json")

model = None
scaler = None
feature_columns = None
load_error = None

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    with open(COLUMNS_PATH) as f:
        feature_columns = json.load(f)
    print(f"Loaded model with {len(feature_columns)} features.")
except FileNotFoundError as e:
    load_error = (
        f"Model artifacts not found ({e}). "
        f"Run `python train_model.py` in the models/ directory first, "
        f"which produces best_model.joblib, scaler.joblib, and "
        f"feature_columns.json in the models/ folder."
    )
    print(f"WARNING: {load_error}")

# Which feature tier to use at inference time. Tier 1 (lexical only) is
# the default because it's instant and needs no network access — ideal
# for a responsive web UI. Change to 2 or 3 if you trained the model on
# a higher tier (must match training tier or predictions will be
# meaningless, since the model won't have learned those columns).
INFERENCE_TIER = 2

# --- Trusted hostname allowlist ---
#
# SECURITY NOTE — read before adding to this list:
# This is a list of EXACT, specific hostnames, not apex domains. That's
# a deliberate choice, not an oversight. Whitelisting an entire apex
# domain (e.g. "google.com") would also silently whitelist every
# subdomain under it — including ones like script.google.com and
# sites.google.com, which have been used in real, documented phishing
# campaigns precisely because attackers know reputation filters trust
# google.com. An exact-hostname allowlist fixes the specific false
# positives we saw (web.whatsapp.com, www.youtube.com, mail.google.com)
# without opening that door.
#
# Matching is exact string equality against the parsed hostname
# (lowercased, no port, no trailing dot) — never a substring/"contains"
# check. A substring check like `"google.com" in url` would let
# `http://google.com.evil-attacker.tk/login` through, since the
# substring appears in that string too. Exact equality doesn't have
# that hole.
#
# This bypasses ML scoring entirely for an exact match, so add hosts
# here sparingly — only for sites you've personally verified are
# getting misclassified, not speculatively. Every entry here is a
# hardcoded rule, not something the model "learned"; see api response's
# "method" field, which reports "allowlist" vs "model" for transparency.
TRUSTED_HOSTNAMES = {
    "whatsapp.com", "www.whatsapp.com", "web.whatsapp.com",
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "google.com", "www.google.com", "mail.google.com", "accounts.google.com",
    "github.com", "www.github.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "amazon.com", "www.amazon.com",
    "wikipedia.org", "www.wikipedia.org", "en.wikipedia.org",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
    "linkedin.com", "www.linkedin.com",
    "netflix.com", "www.netflix.com",
}


def get_hostname(url: str) -> str:
    """Extract a normalized (lowercase, no port, no trailing dot) hostname from a URL."""
    from urllib.parse import urlparse
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0].rstrip(".")
    return host.lower()


def predict_url(url: str) -> dict:
    """
    Run the full pipeline: check the trusted-hostname allowlist first,
    then (if no match) extract features -> align to training columns
    -> scale -> predict. Returns a dict ready to jsonify.
    """
    hostname = get_hostname(url)
    if hostname in TRUSTED_HOSTNAMES:
        return {
            "url": url,
            "verdict": "legitimate",
            "confidence": 0.0,
            "flags": [],
            "method": "allowlist",
            "note": f"'{hostname}' is on the trusted hostname allowlist — not scored by the model.",
        }

    if model is None:
        return {"error": load_error or "Model not loaded."}

    raw_features = extract_features(url, tier=INFERENCE_TIER)

    # Align to the exact column order/set the model was trained on.
    # Any column the model expects but we didn't compute (e.g. because
    # inference tier < training tier) gets filled with -1 ("unknown"),
    # matching how missing tier 2/3 values were handled during training.
    row = [raw_features.get(col, -1) for col in feature_columns]
    X_scaled = scaler.transform([row])


    pred = model.predict(X_scaled)[0]
    proba = model.predict_proba(X_scaled)[0][1] if hasattr(model, "predict_proba") else None

    verdict = "phishing" if pred == 1 else "legitimate"

    # Surface a few of the most human-readable signals so the verdict
    # isn't a black box to the person checking the URL.
    flags = []
    if raw_features.get("has_ip_address"):
        flags.append("Uses a raw IP address instead of a domain name")
    if raw_features.get("suspicious_tld"):
        flags.append("Uses a domain extension commonly abused for phishing")
    if raw_features.get("has_suspicious_word"):
        flags.append("Contains suspicious keywords (login, verify, secure, etc.)")
    if raw_features.get("has_excessive_subdomains"):
        flags.append("Has an unusually large number of subdomains")
    if raw_features.get("brand_in_subdomain_or_path"):
        flags.append("A known brand name appears outside the actual domain")
    if raw_features.get("is_shortened"):
        flags.append("Uses a URL shortener, hiding the real destination")
    if not raw_features.get("uses_https"):
        flags.append("Does not use HTTPS")

    return {
        "url": url,
        "verdict": verdict,
        "confidence": round(float(proba), 4) if proba is not None else None,
        "flags": flags,
        "method": "model",
    }


@app.route("/")
@app.route("/index")
@app.route("/index.py")
@app.route("/api/index")
@app.route("/api/index.py")
def index():
    return render_template("index.html")



@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please provide a 'url' field."}), 400

    result = predict_url(url)
    if "error" in result:
        return jsonify(result), 503

    return jsonify(result)


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok" if model is not None else "model_not_loaded",
        "model_loaded": model is not None,
        "num_features": len(feature_columns) if feature_columns else 0,
    })


if __name__ == "__main__":
    if model is None:
        print("\n" + "=" * 70)
        print("WARNING: Starting server without a loaded model.")
        print(load_error)
        print("The web UI will run but every check will return an error")
        print("until you train a model and restart this server.")
        print("=" * 70 + "\n")
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)

