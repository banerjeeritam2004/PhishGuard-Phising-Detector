# PhishGuard Chrome Extension
ML-powered phishing website detection — auto-analyzes every site you visit.

---

## Project Structure

```
phishing-extension/
├── backend/
│   ├── app.py           ← Flask API (loads your model.pkl)
│   └── requirements.txt
└── extension/
    ├── manifest.json
    ├── background.js    ← Service worker (calls API on every tab)
    ├── content.js       ← Injects warning overlay into phishing pages
    ├── popup.html       ← Extension popup UI
    ├── popup.js
    └── icons/           ← Extension icons
```

---

## Step 1 — Set Up the Backend

### 1.1 Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 1.2 Add your trained model
Copy `model.pkl` (from your ML training script) into the `backend/` folder:
```
backend/
├── app.py
├── model.pkl   ← Place here
└── requirements.txt
```

### 1.3 Start the API server
```bash
python app.py
```
The server runs at `http://127.0.0.1:5000`.  
Test it:
```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

---

## Step 2 — Load the Chrome Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder

The PhishGuard extension will appear in your toolbar.

---

## How It Works

```
You visit a site
      ↓
background.js intercepts the tab URL
      ↓
POST /predict  →  Flask API
      ↓
Feature extraction from URL (30 features)
      ↓
model.pkl → prediction
      ↓
  Phishing?               Safe?
     ↓                      ↓
 Red badge (!)          Green badge (✓)
 Warning overlay        No action
 Browser notification
```

---

## Features Detected (URL-based)

The model uses 30 features from the UCI Phishing Dataset:

| # | Feature | Description |
|---|---------|-------------|
| 1 | IP Address | URL contains raw IP instead of domain |
| 2 | URL Length | Suspicious URL length (>75 = bad) |
| 3 | Shortening Service | bit.ly, tinyurl, etc. |
| 4 | @ Symbol | Causes browser to ignore preceding text |
| 5 | Double Slash | Redirect after // |
| 6 | Prefix-Suffix | Dash in domain name |
| 7 | Sub Domain | Excessive subdomains |
| 8 | SSL Certificate | HTTP vs HTTPS |
| 9 | Domain Age | New domains are suspicious |
| 10 | Favicon | External favicon source |
| ...| ... | ... |

---

## Customisation

### Change API port
Edit line 1 in `background.js` and `popup.js`:
```js
const API_URL = "http://127.0.0.1:YOUR_PORT/predict";
```

### Adjust feature extraction
Edit `extract_features()` in `backend/app.py` to match your training dataset's feature set exactly.

### Disable warning overlay
In `background.js`, comment out the `chrome.tabs.sendMessage` block.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Badge shows `?` | Backend server not running. Start with `python app.py` |
| `model.pkl not found` | Copy `model.pkl` to the `backend/` folder |
| Extension not detecting | Open DevTools → Extensions → PhishGuard → Inspect service worker |
| CORS error | Already handled by `flask-cors` — ensure you installed requirements |

---

## Security Note

The backend runs locally on `127.0.0.1` — your URLs are never sent to any external server.
Only your local ML model processes your browsing data.
