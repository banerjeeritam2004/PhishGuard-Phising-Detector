// PhishGuard - Popup Script (Fixed)

const API_URL = "https://phishguard-phishing-detector.onrender.com";

const FEATURE_NAMES = [
  "IP Address URL", "URL Length", "Shortener", "@ Symbol",
  "Double Slash", "Prefix-Suffix", "Sub Domain", "SSL Cert",
  "Domain Age", "Favicon", "Port", "HTTPS Token",
  "Request URL", "Anchor URL", "Link Tags", "SFH",
  "Email Submit", "Abnormal URL", "Redirect", "Mouseover",
  "Right Click", "Popup", "iFrame", "Domain Register",
  "DNS Record", "Web Traffic", "Page Rank", "Google Index",
  "Backlinks", "Stats Report",
];

function featureClass(val) {
  if (val === 1)  return "good";
  if (val === -1) return "bad";
  return "mid";
}

function setStatus(type, icon, label, sub) {
  const card = document.getElementById("statusCard");
  card.className = "status-card " + type;
  document.getElementById("statusIcon").textContent = icon;
  document.getElementById("statusLabel").textContent = label;
  document.getElementById("statusSub").textContent = sub;
}

function renderResult(data) {
  if (!data || data.error) {
    setStatus("error", "⚙️", "API Error", "Could not reach the detection server");
    return;
  }

  const isPhish = data.is_phishing;

  if (isPhish) {
    setStatus("phish", "🚨", "Phishing Detected", "This site appears malicious — proceed with caution");
  } else {
    setStatus("safe", "✅", "Site Looks Safe", "No phishing indicators detected");
  }

  // URL
  document.getElementById("urlBox").style.display = "block";
  document.getElementById("urlText").textContent = data.url;

  // Confidence
  if (data.confidence != null) {
    const pct = Math.round(data.confidence * 100);
    document.getElementById("confSection").style.display = "block";
    document.getElementById("confVal").textContent = pct + "%";
    const fill = document.getElementById("confFill");
    fill.style.width = pct + "%";
    fill.style.background = isPhish ? "#ef4444" : "#22c55e";
  }

  // Features
  if (data.features && data.features.length) {
    document.getElementById("featuresSection").style.display = "block";
    const grid = document.getElementById("featuresGrid");
    grid.innerHTML = "";
    data.features.slice(0, 14).forEach((val, i) => {
      const cls = featureClass(val);
      const chip = document.createElement("div");
      chip.className = "feature-chip";
      chip.innerHTML = `
        <div class="feature-dot ${cls}"></div>
        <span class="feature-name">${FEATURE_NAMES[i] || "Feature " + i}</span>
      `;
      grid.appendChild(chip);
    });
  }
}

// Check server health and update dot only
async function checkServer() {
  try {
    const res = await fetch(`${API_URL}/health`, { signal: AbortSignal.timeout(3000) });
    const data = await res.json();
    document.getElementById("serverDot").className = "server-dot ok";
    if (!data.model_loaded) {
      document.getElementById("serverBanner").classList.remove("hidden");
    }
    return true;
  } catch {
    document.getElementById("serverDot").className = "server-dot err";
    document.getElementById("serverBanner").classList.remove("hidden");
    return false;
  }
}

// Get current tab URL and call predict directly from popup
async function analyzeCurrentTab() {
  setStatus("checking", "🔍", "Checking…", "Analyzing current page");

  // Get the active tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !tab.url.startsWith("http")) {
    setStatus("error", "🔌", "Cannot check this page", "Extension only works on http/https pages");
    return;
  }

  document.getElementById("urlBox").style.display = "block";
  document.getElementById("urlText").textContent = tab.url;

  // First check if server is alive
  const serverOk = await checkServer();
  if (!serverOk) {
    setStatus("error", "🔌", "Server Offline", "Run: python app.py in the backend folder");
    return;
  }

  // Call predict directly
  try {
    const res = await fetch(`${API_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url }),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      const err = await res.json();
      setStatus("error", "⚙️", "Prediction Error", err.error || "Server returned an error");
      return;
    }

    const data = await res.json();
    renderResult(data);

    // Also save to storage for background sync
    chrome.storage.local.set({ [`result_${tab.id}`]: data });

  } catch (err) {
    setStatus("error", "⚙️", "API Error", "Could not reach the detection server");
    console.error("Predict error:", err);
  }
}

// Recheck button
document.getElementById("recheckBtn").onclick = () => {
  analyzeCurrentTab();
};

// Run on popup open
analyzeCurrentTab();
