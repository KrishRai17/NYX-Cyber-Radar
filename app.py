from flask import Flask, render_template, request
import re
import urllib.request
import json
import socket
import ssl
from datetime import datetime

app = Flask(__name__)

# Client location auto-discovery on startup
client_origin = {"lat": 12.9716, "lon": 77.5946, "city": "Bangalore", "country": "India", "org": "Kristu Jayanti ISP"}

def detect_client_origin():
    global client_origin
    try:
        req = urllib.request.Request("http://ip-api.com/json/", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2.5) as r:
            data = json.loads(r.read().decode())
            if data.get("status") == "success":
                client_origin = {
                    "lat": data.get("lat", 12.9716),
                    "lon": data.get("lon", 77.5946),
                    "city": data.get("city", "Bangalore"),
                    "country": data.get("country", "India"),
                    "org": data.get("org", "Local ISP")
                }
    except Exception as e:
        print(f"Error detecting client origin: {e}")

detect_client_origin()


def get_geo_location(url):
    # Extract domain/host from URL
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.split(":")[0] # strip port
    
    try:
        req_url = f"http://ip-api.com/json/{domain}"
        req = urllib.request.Request(req_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0),
                    "ip": data.get("query", "0.0.0.0"),
                    "org": data.get("org", "Unknown")
                }
    except Exception as e:
        print(f"Error getting geo location for {domain}: {e}")
        
    # Fallback IP lookup
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = "0.0.0.0"
        
    return {
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "ip": ip,
        "org": "Local Host / Private Network"
    }


# Helper: Raw socket WHOIS parser
def get_whois_data(domain):
    try:
        # Step 1: Query IANA
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("whois.iana.org", 43))
        s.send((domain + "\r\n").encode("utf-8"))
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        resp_text = response.decode("utf-8", errors="ignore")
        
        # Parse for referral WHOIS server
        refer_server = None
        for line in resp_text.splitlines():
            if line.strip().startswith("refer:"):
                refer_server = line.split("refer:")[1].strip()
                break
                
        if not refer_server:
            if domain.endswith(".com") or domain.endswith(".net"):
                refer_server = "whois.verisign-grs.com"
            elif domain.endswith(".org"):
                refer_server = "whois.pir.org"
            else:
                return resp_text # No refer, return IANA output
                
        # Step 2: Query registrar WHOIS server
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(3.0)
        s2.connect((refer_server, 43))
        s2.send((domain + "\r\n").encode("utf-8"))
        
        response2 = b""
        while True:
            data = s2.recv(4096)
            if not data:
                break
            response2 += data
        s2.close()
        return response2.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"WHOIS socket query error for {domain}: {e}")
        return ""


# Helper: Extract creation date from WHOIS data
def extract_creation_date(whois_text):
    if not whois_text:
        return None
    patterns = [
        r"(?:Creation Date|Created On|Created|created|Creation-Date):\s*([^\r\n]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, whois_text, re.IGNORECASE)
        if match:
            date_str = match.group(1).strip()
            ymd = re.search(r"(\d{4})[-/](\d{2})[-/](\d{2})", date_str)
            if ymd:
                try:
                    return datetime(int(ymd.group(1)), int(ymd.group(2)), int(ymd.group(3)))
                except ValueError:
                    pass
            for fmt in ("%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y.%m.%d"):
                try:
                    return datetime.strptime(date_str.split(".")[0].split("Z")[0].strip(), fmt)
                except ValueError:
                    pass
    return None


# Helper: Extract SSL Certificate Details
def get_ssl_details(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                try:
                    context_val = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=3.0) as sock_v:
                        with context_val.wrap_socket(sock_v, server_hostname=domain) as ssock_v:
                            cert_val = ssock_v.getpeercert()
                            if cert_val:
                                issuer = dict(x[0] for x in cert_val.get('issuer', []))
                                notAfter = cert_val.get('notAfter', 'Unknown')
                                return {
                                    "active": True,
                                    "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                                    "expiry": notAfter
                                }
                except Exception:
                    pass
                return {
                    "active": True,
                    "issuer": "Self-Signed or Unverified CA",
                    "expiry": "Unknown"
                }
    except Exception as e:
        print(f"SSL probe error for {domain}: {e}")
    return {
        "active": False,
        "issuer": "N/A",
        "expiry": "N/A"
    }


# Helper: Check Security Headers via HEAD request
def check_security_headers(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    headers_status = {
        "hsts": False,
        "x_frame": False,
        "csp": False
    }
    target_url = url
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    try:
        req = urllib.request.Request(target_url, method="HEAD", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            headers = response.info()
            if "Strict-Transport-Security" in headers:
                headers_status["hsts"] = True
            if "X-Frame-Options" in headers:
                headers_status["x_frame"] = True
            if "Content-Security-Policy" in headers:
                headers_status["csp"] = True
    except Exception as e:
        print(f"Security Headers probe error for {domain}: {e}")
        if target_url.startswith("https://"):
            try:
                target_url = target_url.replace("https://", "http://")
                req = urllib.request.Request(target_url, method="HEAD", headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3.0) as response:
                    headers = response.info()
                    if "Strict-Transport-Security" in headers:
                        headers_status["hsts"] = True
                    if "X-Frame-Options" in headers:
                        headers_status["x_frame"] = True
                    if "Content-Security-Policy" in headers:
                        headers_status["csp"] = True
            except Exception:
                pass
    return headers_status


def check_phishing(url, is_new_domain=False):
    score = 0
    reasons = []

    # Check HTTPS
    if not url.startswith("https://"):
        score += 1
        reasons.append("Not using HTTPS")

    # Suspicious keywords
    keywords = ["login", "verify", "bank", "secure", "account"]
    for word in keywords:
        if word in url.lower():
            score += 1
            reasons.append(f"Contains suspicious keyword: {word}")

    # URL length
    if len(url) > 75:
        score += 1
        reasons.append("URL is too long")

    # IP address in URL
    if re.match(r"http[s]?://\d+\.\d+\.\d+\.\d+", url):
        score += 2
        reasons.append("Uses IP address instead of domain")

    # Domain age penalty
    if is_new_domain:
        score += 2
        reasons.append("Domain is newly registered (under 30 days old)")

    # Result
    if score >= 3:
        result = "❌ Dangerous (Phishing Likely)"
    elif score == 2:
        result = "⚠️ Suspicious"
    else:
        result = "✅ Safe"

    return result, reasons


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    reasons = []

    if request.method == "POST":
        url = request.form.get("url")
        result, reasons = check_phishing(url)

    return render_template("index.html", result=result, reasons=reasons)


@app.route("/author")
def author():
    return render_template("author.html")


@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    url = request.form.get("url")
    if not url and request.is_json:
        data = request.get_json() or {}
        url = data.get("url", "")

    if not url:
        return {"status": "error", "message": "No URL provided"}, 400

    domain = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # WHOIS Lookup
    whois_text = get_whois_data(domain)
    creation_date = extract_creation_date(whois_text)
    domain_age_days = None
    is_new = False
    if creation_date:
        age = datetime.now() - creation_date
        domain_age_days = age.days
        if domain_age_days < 30:
            is_new = True

    result, reasons = check_phishing(url, is_new_domain=is_new)
    target_geo = get_geo_location(url)
    
    # SSL Details
    ssl_details = get_ssl_details(domain)
    
    # Security Headers
    headers_details = check_security_headers(url)
    
    return {
        "status": "success",
        "url": url,
        "result": result,
        "reasons": reasons,
        "client_geo": client_origin,
        "target_geo": target_geo,
        "whois_telemetry": {
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else "Unknown",
            "domain_age_days": domain_age_days if domain_age_days is not None else "Unknown",
            "is_new": is_new
        },
        "ssl_telemetry": ssl_details,
        "headers_telemetry": headers_details
    }


if __name__ == "__main__":
    app.run(debug=True)