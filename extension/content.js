// PhishGuard - Content Script
// Extracts DOM-based features from the live page and sends to background

function extractDOMFeatures() {
  const url = window.location.href;
  const html = document.documentElement.innerHTML;
  const anchors = Array.from(document.querySelectorAll("a"));
  const forms = Array.from(document.querySelectorAll("form"));
  const scripts = Array.from(document.querySelectorAll("script"));
  const links = Array.from(document.querySelectorAll("link"));
  const iframes = Array.from(document.querySelectorAll("iframe"));
  const images = Array.from(document.querySelectorAll("img"));
  const domain = window.location.hostname;

  // ── Feature: Request_URL ──────────────────────────────────────────
  // % of objects (img/script/link) loaded from external domain
  const allObjects = [...images, ...scripts, ...links];
  let externalObjects = 0;
  allObjects.forEach(el => {
    const src = el.src || el.href || "";
    if (src && !src.startsWith("data:") && !src.includes(domain) && src.startsWith("http")) {
      externalObjects++;
    }
  });
  const requestURLRatio = allObjects.length > 0 ? externalObjects / allObjects.length : 0;
  const Request_URL = requestURLRatio < 0.22 ? 1 : requestURLRatio < 0.61 ? 0 : -1;

  // ── Feature: URL_of_Anchor ────────────────────────────────────────
  // % of anchor tags pointing to different domain or empty
  let suspiciousAnchors = 0;
  anchors.forEach(a => {
    const href = a.getAttribute("href") || "";
    if (href === "#" || href === "" || href.toLowerCase().startsWith("javascript")) {
      suspiciousAnchors++;
    } else if (href.startsWith("http") && !href.includes(domain)) {
      suspiciousAnchors++;
    }
  });
  const anchorRatio = anchors.length > 0 ? suspiciousAnchors / anchors.length : 0;
  const URL_of_Anchor = anchorRatio < 0.31 ? 1 : anchorRatio < 0.67 ? 0 : -1;

  // ── Feature: Links_in_tags ────────────────────────────────────────
  // meta/script/link tags pointing to external domain
  let externalTagLinks = 0;
  [...scripts, ...links].forEach(el => {
    const src = el.src || el.href || "";
    if (src && src.startsWith("http") && !src.includes(domain)) {
      externalTagLinks++;
    }
  });
  const tagLinkRatio = (scripts.length + links.length) > 0
    ? externalTagLinks / (scripts.length + links.length) : 0;
  const Links_in_tags = tagLinkRatio < 0.17 ? 1 : tagLinkRatio < 0.81 ? 0 : -1;

  // ── Feature: SFH (Server Form Handler) ───────────────────────────
  let SFH = 1;
  forms.forEach(form => {
    const action = (form.getAttribute("action") || "").trim();
    if (action === "" || action === "about:blank") {
      SFH = -1;
    } else if (action.startsWith("http") && !action.includes(domain)) {
      SFH = 0;
    }
  });

  // ── Feature: Submitting_to_email ─────────────────────────────────
  let Submitting_to_email = 1;
  forms.forEach(form => {
    const action = (form.getAttribute("action") || "").toLowerCase();
    if (action.includes("mailto:")) Submitting_to_email = -1;
  });

  // ── Feature: on_mouseover ─────────────────────────────────────────
  const on_mouseover = /onmouseover\s*=\s*["'][^"']*window\.status/i.test(html) ? -1 : 1;

  // ── Feature: RightClick ───────────────────────────────────────────
  const RightClick = /contextmenu|e\.preventDefault\(\)|return\s+false/i.test(html) &&
    /contextmenu/i.test(html) ? -1 : 1;

  // ── Feature: popUpWidnow ──────────────────────────────────────────
  const popUpWidnow = /window\.open\s*\(|alert\s*\(|confirm\s*\(/i.test(html) ? -1 : 1;

  // ── Feature: Iframe ───────────────────────────────────────────────
  let Iframe = 1;
  iframes.forEach(iframe => {
    const display = window.getComputedStyle(iframe).display;
    const visibility = window.getComputedStyle(iframe).visibility;
    const width = parseInt(iframe.getAttribute("width") || "100");
    const height = parseInt(iframe.getAttribute("height") || "100");
    if (display === "none" || visibility === "hidden" || width === 0 || height === 0) {
      Iframe = -1;
    }
  });

  // ── Feature: Favicon ─────────────────────────────────────────────
  let Favicon = 1;
  document.querySelectorAll("link[rel*='icon']").forEach(link => {
    const href = link.getAttribute("href") || "";
    if (href.startsWith("http") && !href.includes(domain)) {
      Favicon = -1;
    }
  });

  // ── Feature: Redirect ─────────────────────────────────────────────
  // Count meta refresh redirects
  let Redirect = 1;
  document.querySelectorAll("meta[http-equiv='refresh']").forEach(() => {
    Redirect = -1;
  });

  // ── Feature: Statistical_report ──────────────────────────────────
  // Check for common phishing page patterns
  const phishingKeywords = /verify.*account|confirm.*password|update.*billing|suspended.*account|login.*secure/i;
  const Statistical_report = phishingKeywords.test(document.title + " " + document.body.innerText.substring(0, 500))
    ? -1 : 1;

  // ── Feature: Google_Index ─────────────────────────────────────────
  // Can't check from content script — use URL-based heuristic
  // New/unknown domains are more likely phishing
  const Google_Index = 1; // Default legit

  // ── Feature: Links_pointing_to_page ──────────────────────────────
  const Links_pointing_to_page = 0; // Cannot determine from page itself

  return {
    Request_URL,
    URL_of_Anchor,
    Links_in_tags,
    SFH,
    Submitting_to_email,
    on_mouseover,
    RightClick,
    popUpWidnow,
    Iframe,
    Favicon,
    Redirect,
    Statistical_report,
    Google_Index,
    Links_pointing_to_page,
  };
}

// Warning overlay
function showWarningOverlay(url, confidence) {
  if (document.getElementById("phishguard-overlay")) return;

  const pct = confidence ? Math.round(confidence * 100) + "%" : "High";

  const overlay = document.createElement("div");
  overlay.id = "phishguard-overlay";
  overlay.innerHTML = `
    <div id="phishguard-backdrop"></div>
    <div id="phishguard-modal">
      <div id="phishguard-icon">⚠️</div>
      <h1 id="phishguard-title">Phishing Site Detected</h1>
      <p id="phishguard-sub">PhishGuard ML has flagged this page as potentially malicious.</p>
      <div id="phishguard-confidence">
        <span>Model Confidence</span>
        <span id="phishguard-conf-val">${pct}</span>
      </div>
      <div id="phishguard-url-box">
        <small>Flagged URL</small>
        <div id="phishguard-url">${url.replace(/&/g,"&amp;").replace(/</g,"&lt;")}</div>
      </div>
      <div id="phishguard-buttons">
        <button id="phishguard-back">← Go Back (Safe)</button>
        <button id="phishguard-proceed">Proceed Anyway</button>
      </div>
      <p id="phishguard-footer">Powered by PhishGuard ML · False positive? <a id="phishguard-dismiss">Dismiss</a></p>
    </div>
  `;

  const style = document.createElement("style");
  style.textContent = `
    #phishguard-overlay * { box-sizing: border-box; font-family: 'Segoe UI', system-ui, sans-serif; }
    #phishguard-backdrop { position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:2147483646;backdrop-filter:blur(4px); }
    #phishguard-modal {
      position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
      z-index:2147483647;background:#0f0f0f;border:1px solid #ef4444;
      border-radius:16px;padding:40px 36px;max-width:480px;width:90%;
      box-shadow:0 0 60px rgba(239,68,68,0.4);text-align:center;
      animation:pg-pop 0.3s cubic-bezier(.175,.885,.32,1.275);
    }
    @keyframes pg-pop { from{opacity:0;transform:translate(-50%,-50%) scale(0.85)} to{opacity:1;transform:translate(-50%,-50%) scale(1)} }
    #phishguard-icon { font-size:52px;margin-bottom:12px; }
    #phishguard-title { color:#ef4444;font-size:24px;font-weight:700;margin:0 0 8px; }
    #phishguard-sub { color:#9ca3af;font-size:14px;margin:0 0 20px; }
    #phishguard-confidence { display:flex;justify-content:space-between;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:8px;padding:10px 14px;margin-bottom:12px; }
    #phishguard-confidence span { color:#d1d5db;font-size:13px; }
    #phishguard-conf-val { color:#ef4444!important;font-weight:700;font-size:15px!important; }
    #phishguard-url-box { background:#1a1a1a;border-radius:8px;padding:10px 14px;margin-bottom:24px;text-align:left; }
    #phishguard-url-box small { color:#6b7280;font-size:11px;display:block;margin-bottom:4px; }
    #phishguard-url { color:#fca5a5;font-size:12px;word-break:break-all; }
    #phishguard-buttons { display:flex;gap:10px;margin-bottom:16px; }
    #phishguard-back,#phishguard-proceed { flex:1;padding:12px;border-radius:8px;border:none;font-size:14px;font-weight:600;cursor:pointer; }
    #phishguard-back { background:#22c55e;color:#000; }
    #phishguard-proceed { background:transparent;border:1px solid #4b5563;color:#9ca3af; }
    #phishguard-footer { color:#4b5563;font-size:12px;margin:0; }
    #phishguard-dismiss { color:#6b7280;cursor:pointer;text-decoration:underline; }
  `;

  document.head.appendChild(style);
  document.body.appendChild(overlay);
  document.getElementById("phishguard-back").onclick = () => history.back();
  document.getElementById("phishguard-proceed").onclick = () => overlay.remove();
  document.getElementById("phishguard-dismiss").onclick = () => overlay.remove();
}

// Listen for messages from background
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "extract_features") {
    try {
      const features = extractDOMFeatures();
      sendResponse({ features });
    } catch (e) {
      sendResponse({ features: null, error: e.message });
    }
  }
  if (msg.action === "show_warning") {
    showWarningOverlay(msg.url, msg.confidence);
  }
  return true;
});
