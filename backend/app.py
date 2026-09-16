"""
Phishing Detection API - v4
============================
Uses only 23 features that can be reliably computed from URL + DOM.
Removed: web_traffic, Page_Rank, DNSRecord, age_of_domain,
         Domain_registeration_length, Google_Index, Links_pointing_to_page
These were always hardcoded neutral (0) and were biasing predictions to "safe".
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle, numpy as np, re, urllib.parse, os, traceback

app = Flask(__name__)
CORS(app)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
model = None
feature_names = None

try:
    payload = pickle.load(open(MODEL_PATH, "rb"))
    model = payload["model"] if isinstance(payload, dict) else payload
    feature_names = payload.get("features") if isinstance(payload, dict) else None
    print(f"✅ Model loaded. Features: {feature_names}")
except FileNotFoundError:
    print("⚠️  model.pkl not found.")
except Exception as e:
    print(f"❌ {e}")
    traceback.print_exc()


# ── URL features ─────────────────────────────────────────────────────

def f_having_IP_Address(url):
    try:
        return -1 if re.search(r'((\d{1,3}\.){3}\d{1,3})', url) else 1
    except: return 1

def f_URL_Length(url):
    n = len(url)
    if n < 54:  return 1
    if n <= 75: return 0
    return -1

def f_Shortining_Service(url):
    p = re.compile(r'bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|'
                   r'cli\.gs|ff\.im|tiny\.cc|snipurl\.com|short\.to|'
                   r'adf\.ly|cur\.lv|j\.mp|buzurl\.com|cutt\.us|v\.gd')
    return -1 if p.search(url) else 1

def f_having_At_Symbol(url):       return -1 if "@" in url else 1
def f_double_slash_redirecting(url): return -1 if url.rfind("//") > 6 else 1

def f_Prefix_Suffix(url):
    try:
        return -1 if "-" in urllib.parse.urlparse(url).netloc else 1
    except: return 1

def f_having_Sub_Domain(url):
    try:
        d = urllib.parse.urlparse(url).netloc
        if d.startswith("www."): d = d[4:]
        dots = d.count(".")
        if dots == 1: return 1
        if dots == 2: return 0
        return -1
    except: return -1

def f_SSLfinal_State(url):   return 1 if url.startswith("https://") else -1

def f_port(url):
    try:
        p = urllib.parse.urlparse(url).port
        if p is None: return 1
        return 1 if p in [80, 443] else -1
    except: return 1

def f_HTTPS_token(url):
    try:
        return -1 if "https" in urllib.parse.urlparse(url).netloc.lower() else 1
    except: return 1

def f_Abnormal_URL(url):
    try:
        d = urllib.parse.urlparse(url).netloc
        return 1 if d and d in url else -1
    except: return -1

def f_Submitting_to_email_url(url):
    return -1 if "mailto:" in url.lower() else 1


def extract_url_features(url):
    return {
        "having_IP_Address":        f_having_IP_Address(url),
        "URL_Length":               f_URL_Length(url),
        "Shortining_Service":       f_Shortining_Service(url),
        "having_At_Symbol":         f_having_At_Symbol(url),
        "double_slash_redirecting": f_double_slash_redirecting(url),
        "Prefix_Suffix":            f_Prefix_Suffix(url),
        "having_Sub_Domain":        f_having_Sub_Domain(url),
        "SSLfinal_State":           f_SSLfinal_State(url),
        "port":                     f_port(url),
        "HTTPS_token":              f_HTTPS_token(url),
        "Abnormal_URL":             f_Abnormal_URL(url),
        "Submitting_to_email_url":  f_Submitting_to_email_url(url),
    }


def build_feature_vector(url_feats, dom):
    """
    Build 23-feature vector matching model training order exactly.
    DOM features fall back to neutral (0 or 1) if not provided.
    """
    d = dom or {}
    vec = [
        int(url_feats["having_IP_Address"]),            # 1
        int(url_feats["URL_Length"]),                   # 2
        int(url_feats["Shortining_Service"]),           # 3
        int(url_feats["having_At_Symbol"]),             # 4
        int(url_feats["double_slash_redirecting"]),     # 5
        int(url_feats["Prefix_Suffix"]),                # 6
        int(url_feats["having_Sub_Domain"]),            # 7
        int(url_feats["SSLfinal_State"]),               # 8
        int(url_feats["port"]),                         # 9
        int(url_feats["HTTPS_token"]),                  # 10
        int(url_feats["Abnormal_URL"]),                 # 11
        int(d.get("Favicon", 1)),                       # 12 — DOM
        int(d.get("Request_URL", 1)),                   # 13 — DOM
        int(d.get("URL_of_Anchor", 0)),                 # 14 — DOM ⚠️ important
        int(d.get("Links_in_tags", 0)),                 # 15 — DOM
        int(d.get("SFH", 1)),                           # 16 — DOM
        int(d.get("Submitting_to_email",
            url_feats["Submitting_to_email_url"])),      # 17 — DOM preferred
        int(d.get("Redirect", 1)),                      # 18 — DOM
        int(d.get("on_mouseover", 1)),                  # 19 — DOM
        int(d.get("RightClick", 1)),                    # 20 — DOM
        int(d.get("popUpWidnow", 1)),                   # 21 — DOM
        int(d.get("Iframe", 1)),                        # 22 — DOM
        int(d.get("Statistical_report", 1)),            # 23 — DOM
    ]
    return vec


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url", "").strip()
    dom = data.get("dom_features", None)

    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    try:
        url_feats = extract_url_features(url)
        features = build_feature_vector(url_feats, dom)

        arr = np.array(features, dtype=np.int64).reshape(1, -1)

        # Pass as DataFrame if model was trained with feature names
        if feature_names:
            import pandas as pd
            arr = pd.DataFrame([features], columns=feature_names)

        prediction = int(model.predict(arr)[0])
        is_phishing = (prediction == -1)

        confidence = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(arr)[0]
            confidence = float(max(proba))

        result = {
            "url": url,
            "is_phishing": is_phishing,
            "label": "Phishing" if is_phishing else "Legitimate",
            "confidence": confidence,
            "features": features,
            "dom_used": dom is not None,
        }
        src = "URL+DOM" if dom else "URL only"
        print(f"{'🚨' if is_phishing else '✅'} {result['label']} ({confidence:.1%}) [{src}] — {url}")
        return jsonify(result)

    except Exception as e:
        print(f"❌ Error:\n{traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None, "test": "NEW_CODE_123"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
