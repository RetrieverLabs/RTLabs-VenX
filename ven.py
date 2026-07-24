import csv
import json
import urllib.request
import urllib.parse
import base64
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from flask import Flask, render_template_string
import yfinance as yf

app = Flask(__name__)

# =====================================================================
# 1. CORE INTELLIGENCE LOGIC
# =====================================================================
def fetch_cisa_kev_database():
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(cisa_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read())
    except Exception:
        return None

def extract_real_news_url(google_news_url):
    try:
        if "/rss/articles/" in google_news_url:
            encoded_part = google_news_url.split("/rss/articles/")[1].split("?")[0]
            padding = len(encoded_part) % 4
            if padding:
                encoded_part += "=" * (4 - padding)
            
            decoded_bytes = base64.b64decode(encoded_part)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            if "http" in decoded_str:
                start_idx = decoded_str.find("http")
                clean_url = ""
                for char in decoded_str[start_idx:]:
                    if char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;=%":
                        clean_url += char
                    else:
                        break
                return clean_url.split("?")[0] if "?" in clean_url else clean_url
    except Exception:
        pass
    return google_news_url.split("?")[0] if "?" in google_news_url else google_news_url

def fetch_vendor_news_alerts(vendor_name):
    keywords_list = ["compromised", "hacked", "breached", "incident", "advisory"]
    keywords_query = '("compromised" OR "hacked" OR "breached" OR "incident" OR "advisory")'
    search_query = f'"{vendor_name}" AND {keywords_query}'
    
    rss_url = f"https://news.google.com/rss/search?q={urllib.parse.quote(search_query)}&hl=en-US&gl=US&ceid=US:en"
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(rss_url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as response:
            root = ET.fromstring(response.read())
        
        for item in root.findall(".//item"):
            title = item.find("title").text if item.find("title") is not None else "Unknown Title"
            raw_link = item.find("link").text if item.find("link") is not None else ""
            link = extract_real_news_url(raw_link)
            pub_date = item.find("pubDate").text[:16] if item.find("pubDate") is not None else ""
            
            if " - " in title:
                title = title.rsplit(" - ", 1)[0]
                
            matched_keyword = "Contextual Match"
            for kw in keywords_list:
                if kw in title.lower():
                    matched_keyword = kw.capitalize()
                    break
                    
            return {"title": title, "link": link, "date": pub_date, "keyword": matched_keyword}
    except Exception:
        pass
    return None

def calculate_vendor_score(vendor, cisa_db):
    vendor_name = vendor["name"].lower()
    active_exploits = []
    
    if not cisa_db or "vulnerabilities" not in cisa_db:
        return 0
        
    one_year_ago = datetime.now() - timedelta(days=365)
    
    for vuln in cisa_db["vulnerabilities"]:
        if vendor_name in vuln.get("vendorProject", "").lower():
            date_added_str = vuln.get("dateAdded", "")
            try:
                date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
            except ValueError:
                continue
                
            if date_added >= one_year_ago:
                active_exploits.append({
                    "cve_id": vuln.get("cveID"),
                    "product": vuln.get("product", "Unknown Product"),
                    "description": vuln.get("shortDescription", "No description provided."),
                    "date_added": date_added_str
                })
                
    vendor["active_cisa_vulnerabilities"] = active_exploits
    score = len(active_exploits) * 10
    return min(score, 100)

def fetch_stock_impact(ticker, cve_date_str):
    if not ticker or ticker.upper() in ["N/A", "NONE", "PRIVATE", ""]:
        return None
    try:
        stock = yf.Ticker(ticker)
        cve_date = datetime.strptime(cve_date_str, "%Y-%m-%d")
        
        # Look back 5 days to account for weekends/market closures
        start_date = cve_date - timedelta(days=5)
        end_date = cve_date + timedelta(days=7)
        
        hist_then = stock.history(start=start_date.strftime("%Y-%m-%d"), end=end_date.strftime("%Y-%m-%d"))
        hist_today = stock.history(period="1d")
        
        if not hist_then.empty and not hist_today.empty:
            price_then = float(hist_then["Close"].iloc[0])
            price_today = float(hist_today["Close"].iloc[-1])
            pct_change = ((price_today - price_then) / price_then) * 100
            
            return {
                "ticker": ticker.upper(),
                "cve_date": cve_date_str,
                "price_then": round(price_then, 2),
                "price_today": round(price_today, 2),
                "change_pct": round(pct_change, 2)
            }
    except Exception:
        pass
    return None

def load_vendor_portfolio(filepath="vendors.csv"):
    portfolio = []
    try:
        with open(filepath, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                portfolio.append({
                    "name": row["name"].strip(),
                    "previous_score": int(row["previous_score"]),
                    "business_criticality": row["business_criticality"].strip(),
                    "ticker": row.get("ticker", "N/A").strip(),
                    "active_cisa_vulnerabilities": []
                })
        return portfolio
    except FileNotFoundError:
        return []

# =====================================================================
# 2. SIDEBAR DASHBOARD HTML TEMPLATE
# =====================================================================
HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CCR Active Threat Scoreboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; margin: 0; padding: 15px; color: #333; }
        .header { display: flex; justify-content: space-between; align-items: center; background: #fff; padding: 12px 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 12px; }
        
        /* Main Layout Grid */
        .dashboard-container { display: flex; gap: 10px; align-items: stretch; }
        .main-stage { flex: 1; min-width: 0; }
        
        /* Dedicated Visible Vertical Divider Bar */
        .divider {
            width: 3px;
            background-color: #cbd5e1;
            align-self: stretch;
            margin: 0 10px;
            border-radius: 2px;
        }

        .sidebar { 
            width: 280px; 
            flex-shrink: 0; 
            background: #fff; 
            border-radius: 8px; 
            padding: 15px; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.08); 
            height: fit-content; 
        }

        .section-title { font-size: 0.85em; font-weight: bold; margin: 8px 0 6px 0; display: flex; align-items: center; gap: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
        .section-title.high { color: #d32f2f; }
        .section-title.low { color: #2e7d32; }

        /* Row Container - Visible limit set to ~3 cards */
        .card-row { display: flex; gap: 12px; overflow-x: auto; padding-bottom: 8px; margin-bottom: 12px; max-width: 100%; }
        .card-row::-webkit-scrollbar { height: 6px; }
        .card-row::-webkit-scrollbar-thumb { background: #ccc; border-radius: 3px; }

        /* Fixed Width Card */
        .card { flex: 0 0 280px; height: 250px; background: #fff; padding: 12px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); border-top: 4px solid #ccc; display: flex; flex-direction: column; justify-content: space-between; box-sizing: border-box; }
        .card.CRITICAL { border-top-color: #e74c3c; }
        .card.MEDIUM { border-top-color: #f39c12; }
        .card.LOW { border-top-color: #2ecc71; }

        .card-header { display: flex; justify-content: space-between; align-items: flex-start; }
        .vendor-title { font-size: 0.9em; font-weight: bold; margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 160px; }
        .criticality { font-size: 0.75em; color: #666; margin-top: 2px; }

        .badge { padding: 2px 6px; border-radius: 4px; color: #fff; font-size: 0.7em; font-weight: bold; }
        .badge.CRITICAL { background: #e74c3c; }
        .badge.MEDIUM { background: #f39c12; }
        .badge.LOW { background: #2ecc71; }

        .scores { font-size: 0.85em; font-weight: bold; background: #f8f9fa; padding: 4px 8px; border-radius: 4px; margin: 6px 0; display: flex; justify-content: space-between; }

        .details-box { font-size: 0.76em; background: #fafafa; border: 1px solid #eef0f2; padding: 8px; border-radius: 4px; height: 145px; overflow-y: auto; line-height: 1.4; }
        .details-box::-webkit-scrollbar { width: 4px; }
        .details-box::-webkit-scrollbar-thumb { background: #ddd; border-radius: 2px; }
        
        .field-group { margin-bottom: 6px; padding-bottom: 6px; border-bottom: 1px dashed #e0e0e0; }
        .field-group:last-child { margin-bottom: 0; padding-bottom: 0; border-bottom: none; }

        /* Sidebar Item Styling */
        .sidebar-title { font-size: 0.9em; font-weight: bold; margin: 0 0 10px 0; padding-bottom: 6px; border-bottom: 2px solid #333; display: flex; align-items: center; gap: 6px; }
        .stock-card { background: #f8f9fa; border: 1px solid #e9ecef; padding: 10px; border-radius: 6px; margin-bottom: 10px; font-size: 0.8em; }
        .stock-header { display: flex; justify-content: space-between; font-weight: bold; margin-bottom: 4px; }
        .stock-change { font-weight: bold; padding: 2px 4px; border-radius: 3px; font-size: 0.85em; }
        .stock-change.up { color: #2e7d32; background: #e8f5e9; }
        .stock-change.down { color: #c62828; background: #ffebee; }

        .btn { background: #0066cc; color: #fff; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 0.85em; }
        .btn:hover { background: #0052a3; }
        .empty-row { font-size: 0.85em; color: #888; font-style: italic; padding: 10px; }
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h2 style="margin:0; font-size: 1.15em;">🛡️ CCR Active Threat Scoreboard</h2>
            <small style="color:#666; font-size:0.75em;">Last updated: {{ last_updated }}</small>
        </div>
        <a href="/" class="btn">🔄 Refresh Feed</a>
    </div>

    <div class="dashboard-container">
        <!-- LEFT: MAIN CARD ROWS -->
        <div class="main-stage">
            
            <!-- ROW 1: CRITICAL & MEDIUM RISK -->
            <div class="section-title high">🔴 High & Medium Risk Vendors (Score ≥ 50)</div>
            <div class="card-row">
                {% set high_risk_vendors = vendors | selectattr("current_score", ">=", 50) | list %}
                {% if high_risk_vendors %}
                    {% for v in high_risk_vendors %}
                        {% set status = "CRITICAL" if v.current_score >= 75 else "MEDIUM" %}
                        <div class="card {{ status }}">
                            <div>
                                <div class="card-header">
                                    <div>
                                        <div class="vendor-title" title="{{ v.name }}">{{ v.name }}</div>
                                        <div class="criticality">{{ v.business_criticality }}</div>
                                    </div>
                                    <span class="badge {{ status }}">{{ status }}</span>
                                </div>

                                <div class="scores">
                                    <span>Score: {{ v.current_score }}</span>
                                    <span style="color:#777; font-weight:normal;">Was: {{ v.previous_score }}</span>
                                </div>
                            </div>

                            <div class="details-box">
                                {% if v.active_cisa_vulnerabilities %}
                                    {% set top = v.active_cisa_vulnerabilities[0] %}
                                    <div class="field-group">
                                        <div><strong>⚠️ CISA CVE:</strong> {{ top.cve_id }}</div>
                                        <div><strong>Product:</strong> {{ top.product }}</div>
                                        <div><strong>Date Added:</strong> {{ top.date_added }}</div>
                                        <a href="https://nvd.nist.gov/vuln/detail/{{ top.cve_id }}" target="_blank">View NVD Advisory 🔗</a>
                                    </div>
                                {% endif %}

                                {% if v.latest_news_alert %}
                                    <div class="field-group">
                                        <div><strong>📰 Live Security Alert:</strong></div>
                                        <div>{{ v.latest_news_alert.title }}</div>
                                        <div><strong>Keyword:</strong> {{ v.latest_news_alert.keyword }}</div>
                                        <div><strong>Published:</strong> {{ v.latest_news_alert.date }}</div>
                                        <a href="{{ v.latest_news_alert.link }}" target="_blank">Read Full Article 🔗</a>
                                    </div>
                                {% endif %}

                                {% if not v.active_cisa_vulnerabilities and not v.latest_news_alert %}
                                    <div style="color:#888;">No active exploit or news details found.</div>
                                {% endif %}
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <div class="empty-row">🟢 Clear: No High or Medium risk vendors found.</div>
                {% endif %}
            </div>

            <!-- ROW 2: LOW RISK & CLEAR -->
            <div class="section-title low">🟢 Low Risk & Clear Vendors (Score < 50)</div>
            <div class="card-row">
                {% set low_risk_vendors = vendors | selectattr("current_score", "<", 50) | list %}
                {% if low_risk_vendors %}
                    {% for v in low_risk_vendors %}
                        <div class="card LOW">
                            <div>
                                <div class="card-header">
                                    <div>
                                        <div class="vendor-title" title="{{ v.name }}">{{ v.name }}</div>
                                        <div class="criticality">{{ v.business_criticality }}</div>
                                    </div>
                                    <span class="badge LOW">LOW</span>
                                </div>

                                <div class="scores">
                                    <span>Score: {{ v.current_score }}</span>
                                    <span style="color:#777; font-weight:normal;">Was: {{ v.previous_score }}</span>
                                </div>
                            </div>

                            <div class="details-box">
                                {% if v.latest_news_alert %}
                                    <div class="field-group">
                                        <div><strong>📰 Live Security Alert:</strong></div>
                                        <div>{{ v.latest_news_alert.title }}</div>
                                        <div><strong>Keyword:</strong> {{ v.latest_news_alert.keyword }}</div>
                                        <div><strong>Published:</strong> {{ v.latest_news_alert.date }}</div>
                                        <a href="{{ v.latest_news_alert.link }}" target="_blank">Read Full Article 🔗</a>
                                    </div>
                                {% else %}
                                    <div style="color:#2e7d32; font-weight:bold; margin-bottom: 4px;">🟢 All systems clear</div>
                                    <div style="color:#666;">No active CISA vulnerabilities found in last 365 days.</div>
                                {% endif %}
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <div class="empty-row">No low risk vendors in system.</div>
                {% endif %}
            </div>

        </div>

        <!-- CENTER: VISIBLE DIVIDER BAR -->
        <div class="divider"></div>

        <!-- RIGHT: MARKET TREMORS SIDEBAR -->
        <div class="sidebar">
            <div class="sidebar-title">📈 Market Tremors (via Yahoo Finance)</div>
            <small style="color:#666; display:block; margin-bottom: 10px; font-size:0.75em;">Stock impact since CISA Exploit Date Added:</small>
            
            {% set count = [] %}
            {% for v in vendors %}
                {% if v.current_score >= 50 and v.active_cisa_vulnerabilities and v.stock_data %}
                    {% set _ = count.append(1) %}
                    <div class="stock-card">
                        <div class="stock-header">
                            <span>{{ v.name }} ({{ v.stock_data.ticker }})</span>
                            <span class="stock-change {{ 'up' if v.stock_data.change_pct >= 0 else 'down' }}">
                                {{ '+' if v.stock_data.change_pct >= 0 }}{{ v.stock_data.change_pct }}%
                            </span>
                        </div>
                        <div style="color:#555; margin-top: 4px;">
                            <div>CVE Date: {{ v.stock_data.cve_date }}</div>
                            <div>Price Then: ${{ v.stock_data.price_then }}</div>
                            <div>Price Today: ${{ v.stock_data.price_today }}</div>
                        </div>
                    </div>
                {% endif %}
            {% endfor %}

            {% if not count %}
                <div style="font-size: 0.8em; color: #888; font-style: italic;">
                    No public stock impact data available for current critical vendors.
                </div>
            {% endif %}
        </div>
    </div>

</body>
</html>
"""

# =====================================================================
# 3. ROUTE HANDLER
# =====================================================================
@app.route("/")
def dashboard():
    vendor_registry = load_vendor_portfolio("vendors.csv")
    
    if vendor_registry:
        live_kev_database = fetch_cisa_kev_database()
        for vendor in vendor_registry:
            vendor["current_score"] = calculate_vendor_score(vendor, live_kev_database)
            vendor["latest_news_alert"] = fetch_vendor_news_alerts(vendor["name"])
            
            # Fetch stock impact if critical/medium and has active vulnerabilities
            if vendor["current_score"] >= 50 and vendor["active_cisa_vulnerabilities"]:
                cve_date = vendor["active_cisa_vulnerabilities"][0]["date_added"]
                vendor["stock_data"] = fetch_stock_impact(vendor["ticker"], cve_date)
            else:
                vendor["stock_data"] = None
            
        vendor_registry.sort(key=lambda x: x.get('current_score', 0), reverse=True)

    return render_template_string(
        HTML_PAGE, 
        vendors=vendor_registry, 
        last_updated=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
