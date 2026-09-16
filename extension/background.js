// PhishGuard - Background Service Worker v2
// Collects DOM features from content script, then calls API

const API_URL = "http://127.0.0.1:5000/predict";
const CACHE = {};

const BADGE = {
  safe:     { color: "#22c55e", text: "✓" },
  phishing: { color: "#ef4444", text: "!" },
  checking: { color: "#f59e0b", text: "…" },
  error:    { color: "#6b7280", text: "?" },
};

function setBadge(tabId, type) {
  chrome.action.setBadgeText({ tabId, text: BADGE[type].text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE[type].color });
}

// Ask content script for DOM features, with timeout fallback
function getDOMFeatures(tabId) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 3000); // 3s timeout
    try {
      chrome.tabs.sendMessage(tabId, { action: "extract_features" }, (resp) => {
        clearTimeout(timeout);
        if (chrome.runtime.lastError || !resp) {
          resolve(null);
        } else {
          resolve(resp.features || null);
        }
      });
    } catch {
      clearTimeout(timeout);
      resolve(null);
    }
  });
}

async function checkURL(url, tabId) {
  if (!url || !url.startsWith("http")) return;

  // Use cache
  if (CACHE[url]) {
    handleResult(CACHE[url], tabId);
    return;
  }

  setBadge(tabId, "checking");

  // Wait a moment for page to load enough for DOM extraction
  await new Promise(r => setTimeout(r, 1500));

  // Get DOM features from content script
  const domFeatures = await getDOMFeatures(tabId);

  try {
    const body = { url };
    if (domFeatures) body.dom_features = domFeatures;

    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!res.ok) throw new Error("API error " + res.status);

    const data = await res.json();
    CACHE[url] = data;
    chrome.storage.local.set({ [`result_${tabId}`]: data });
    handleResult(data, tabId);

  } catch (err) {
    setBadge(tabId, "error");
    chrome.storage.local.set({ [`result_${tabId}`]: { error: true, url } });
  }
}

function handleResult(data, tabId) {
  if (data.is_phishing) {
    setBadge(tabId, "phishing");
    chrome.notifications.create(`phish_${tabId}_${Date.now()}`, {
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "⚠️ Phishing Site Detected!",
      message: `This site may be trying to steal your information.`,
      priority: 2,
    });
    chrome.tabs.sendMessage(tabId, {
      action: "show_warning",
      url: data.url,
      confidence: data.confidence,
    }).catch(() => {});
  } else {
    setBadge(tabId, "safe");
  }
}

// Tab navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    delete CACHE[tab.url]; // Always recheck on full load
    checkURL(tab.url, tabId);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (tab?.url) checkURL(tab.url, tabId);
  });
});

// Messages from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "get_result") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      chrome.storage.local.get(`result_${tabId}`, (data) => {
        sendResponse({ result: data[`result_${tabId}`], tabId });
      });
    });
    return true;
  }
  if (msg.action === "recheck") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (tab?.url) {
        delete CACHE[tab.url];
        chrome.storage.local.remove(`result_${tab.id}`);
        checkURL(tab.url, tab.id);
        sendResponse({ ok: true });
      }
    });
    return true;
  }
});
