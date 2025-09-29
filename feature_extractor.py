import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
import socket
import datetime
import pandas as pd
import whois
from datetime import datetime

import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import datetime
import whois
import socket, ssl

# ---------------------------
# 1. Having IP Address
# ---------------------------
def extract_having_IP_Address(url):
    domain = urllib.parse.urlparse(url).netloc.split(':')[0]
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, domain):
        parts = domain.split('.')
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                return -1
        return 1
    return -1

# ---------------------------
# 2. URL Length
# ---------------------------
def extract_URL_Length(url):
    length = len(url)
    if length < 54:
        return -1
    elif 54 <= length <= 75:
        return 0
    else:
        return 1

# ---------------------------
# 3. Shortening Service
# ---------------------------
def extract_Shortining_Service(url):
    shortening_services = [
        "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co",
        "is.gd", "buff.ly", "shorte.st", "cutt.ly", "bit.do"
    ]
    return 1 if any(service in url for service in shortening_services) else -1

# ---------------------------
# 4. Having @ Symbol
# ---------------------------
def extract_having_At_Symbol(url):
    return 1 if '@' in url else -1

# ---------------------------
# 5. Double Slash Redirecting
# ---------------------------
def extract_double_slash_redirecting(url):
    pos = url.find('//', 7)
    return 1 if pos != -1 else -1

# ---------------------------
# 6. Prefix/Suffix in Domain
# ---------------------------
def extract_Prefix_Suffix(url):
    domain = urllib.parse.urlparse(url).netloc
    return 1 if '-' in domain else -1

# ---------------------------
# 7. Having Subdomain
# ---------------------------
def extract_having_Sub_Domain(url):
    domain = urllib.parse.urlparse(url).netloc
    dots = domain.count('.')
    if dots == 1:
        return -1
    elif dots == 2:
        return 0
    else:
        return 1

# ---------------------------
# 8. SSL Final State
# ---------------------------
def extract_SSLfinal_State(url):
    try:
        domain = urllib.parse.urlparse(url).netloc
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            notAfter = cert['notAfter']
            expire_date = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.datetime.utcnow()).days
            if days_left > 365:
                return -1
            elif 0 < days_left <= 365:
                return 0
            else:
                return 1
    except Exception:
        return 1

# ---------------------------
# 9. Domain Registration Length
# ---------------------------
def extract_Domain_registeration_length(url):
    try:
        domain_name = urlparse(url).netloc
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]

        if creation_date and expiration_date:
            reg_length = (expiration_date - creation_date).days
            return -1 if reg_length > 365 else 1
        else:
            return 1
    except:
        return 1

# ---------------------------
# 10. Favicon
# ---------------------------
def extract_Favicon(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        favicon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        if favicon:
            href = favicon.get('href', '')
            domain = urllib.parse.urlparse(url).netloc
            return -1 if (domain in href or href.startswith('/')) else 1
        return 1
    except:
        return 1

# ---------------------------
# 11. Port
# ---------------------------
def extract_port(url):
    domain = urllib.parse.urlparse(url).netloc
    if ':' in domain:
        port = int(domain.split(':')[1])
        return 1 if port not in [80, 443] else -1
    return -1

# ---------------------------
# 12. HTTPS Token
# ---------------------------
def extract_HTTPS_token(url):
    domain = urllib.parse.urlparse(url).netloc
    return 1 if 'https' in domain else -1

# ---------------------------
# 13. Request URL
# ---------------------------
def extract_Request_URL(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        total, external = 0, 0
        domain = urllib.parse.urlparse(url).netloc
        tags = soup.find_all(['img', 'script', 'iframe'])
        for tag in tags:
            total += 1
            src = tag.get('src')
            if src:
                src_domain = urllib.parse.urlparse(src).netloc
                if src_domain and src_domain != domain:
                    external += 1
        if total == 0:
            return -1
        ratio = external / total
        if ratio < 0.22:
            return -1
        elif 0.22 <= ratio <= 0.61:
            return 0
        else:
            return 1
    except:
        return 1

# ---------------------------
# 14. URL of Anchor
# ---------------------------
def extract_URL_of_Anchor(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        anchors = soup.find_all('a')
        total = len(anchors)
        external = 0
        domain = urllib.parse.urlparse(url).netloc
        for a in anchors:
            href = a.get('href')
            if href:
                href_domain = urllib.parse.urlparse(href).netloc
                if href_domain and href_domain != domain:
                    external += 1
        if total == 0:
            return -1
        ratio = external / total
        if ratio < 0.31:
            return -1
        elif 0.31 <= ratio <= 0.67:
            return 0
        else:
            return 1
    except:
        return 1

def extract_Links_in_tags(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        links = soup.find_all('link')
        total = len(links)
        external = 0
        domain = urllib.parse.urlparse(url).netloc
        for link in links:
            href = link.get('href')
            if href:
                href_domain = urllib.parse.urlparse(href).netloc
                if href_domain and href_domain != domain:
                    external += 1
        if total == 0:
            return -1   # no suspicious links → legitimate
        ratio = external / total
        if ratio < 0.17:
            return -1  # safe
        elif 0.17 <= ratio <= 0.81:
            return 0   # suspicious
        else:
            return 1   # phishing
    except:
        return 1   # failure = suspicious

# ------------------------------
# 2. SFH (Server Form Handler)
# ------------------------------
def extract_SFH(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            return -1  # no forms = safe
        domain = urllib.parse.urlparse(url).netloc
        for form in forms:
            action = form.get('action')
            if not action or action == "" or action.lower().startswith("javascript"):
                return 1   # phishing
            action_domain = urllib.parse.urlparse(action).netloc
            if action_domain != "" and action_domain != domain:
                return 0   # suspicious
        return -1  # safe
    except:
        return 1   # error = suspicious

# ------------------------------
# 3. Submitting to email
# ------------------------------
def extract_Submitting_to_email(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if 'mailto:' in r.text else -1
    except:
        return 1

# ------------------------------
# 4. Abnormal URL
# ------------------------------
def extract_Abnormal_URL(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path
        if re.search(r'@', url): return 1
        if re.search(r'//', path): return 1
        if '-' in hostname: return 1
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname): return 1
        return -1
    except:
        return 1

# ------------------------------
# 5. Page Rank (heuristic)
# ------------------------------
def extract_Page_Rank(url):
    domain = urlparse(url).netloc.lower()
    trusted_sites = [
        "google.com", "wikipedia.org", "amazon.com", "facebook.com",
        "twitter.com", "linkedin.com", "youtube.com"
    ]
    if any(site in domain for site in trusted_sites):
        return -1  # legitimate
    if len(domain) > 30:
        return 1   # phishing
    return 0      # suspicious

# ------------------------------
# 6. Redirects
# ------------------------------
def extract_Redirect(url):
    try:
        r = requests.head(url, allow_redirects=True, timeout=5)
        return 1 if len(r.history) > 1 else -1
    except:
        return 1

# ------------------------------
# 7. Mouseover / RightClick / Popup / Iframe
# ------------------------------
def extract_on_mouseover(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "onmouseover" in r.text.lower() else -1
    except:
        return 1

def extract_RightClick(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "event.button==2" in r.text else -1
    except:
        return 1

def extract_popUpWidnow(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "alert(" in r.text else -1
    except:
        return 1

def extract_Iframe(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        return 1 if soup.find('iframe') else -1
    except:
        return 1

# ------------------------------
# 8. Age of domain (placeholder)
# ------------------------------
def extract_age_of_domain(url):
    # Ideally: WHOIS lookup, check creation_date
    # For now return suspicious
    return 1

# ------------------------------
# 9. DNS Record
# ------------------------------
def extract_DNSRecord(url):
    domain = urllib.parse.urlparse(url).netloc
    try:
        socket.gethostbyname(domain)
        return -1  # resolved → legitimate
    except:
        return 1   # phishing

# ------------------------------
# 10. Impersonating Brand
# ------------------------------
def extract_Impersonating_Brand(url):
    fake_brands = ['paypal','apple','google','gmail','facebook','amazon','microsoft','netflix','bankofamerica','ebay']
    suspicious_keywords = ['support','account','secure','login','update','verify']
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    for brand in fake_brands:
        if brand in domain:
            for keyword in suspicious_keywords:
                if keyword in domain:
                    return 1
            return 1
    return -1

# ------------------------------
# 11. Web Traffic (heuristic)
# ------------------------------
def extract_web_traffic(url):
    try:
        parsed = urlparse(url)
        path_len = len(parsed.path)
        query_len = len(parsed.query)
        total_len = len(url)
        if total_len > 150 or path_len > 40 or query_len > 20:
            return 1   # phishing
        elif total_len > 75:
            return 0   # suspicious
        else:
            return -1  # legitimate
    except:
        return 1

# ------------------------------
# 12. Google Index (heuristic)
# ------------------------------
def extract_Google_Index(url):
    parsed = urlparse(url)
    if parsed.scheme == 'https' and len(parsed.netloc) < 20:
        return -1  # legitimate
    elif parsed.scheme == 'http':
        return 0   # suspicious
    else:
        return 1   # phishing

# ------------------------------
# 13. Links pointing to page
# ------------------------------
def extract_Links_pointing_to_page(url):
    parsed = urlparse(url)
    path_len = len(parsed.path.split('/'))
    query_len = len(parsed.query.split('&')) if parsed.query else 0
    if path_len > 5 or query_len > 3:
        return 1   # phishing
    elif path_len > 3:
        return 0   # suspicious
    else:
        return -1  # legitimate

# ------------------------------
# 14. Statistical Report
# ------------------------------
def extract_Statistical_report(url):
    count = url.count('@') + url.count('-') + url.count('//')
    if count > 3:
        return 1   # phishing
    elif count == 2 or count == 3:
        return 0   # suspicious
    else:
        return -1  # legitimate
def extract_features(url):
    features = {
        'having_IP_Address': extract_having_IP_Address(url),
        'URL_Length': extract_URL_Length(url),
        'Shortining_Service': extract_Shortining_Service(url),
        'having_At_Symbol': extract_having_At_Symbol(url),
        'double_slash_redirecting': extract_double_slash_redirecting(url),
        'Prefix_Suffix': extract_Prefix_Suffix(url),
        'having_Sub_Domain': extract_having_Sub_Domain(url),
        'SSLfinal_State': extract_SSLfinal_State(url),
        'Domain_registeration_length': extract_Domain_registeration_length(url),
        'Favicon': extract_Favicon(url),
        'port': extract_port(url),
        'HTTPS_token': extract_HTTPS_token(url),
        'Request_URL': extract_Request_URL(url),
        'URL_of_Anchor': extract_URL_of_Anchor(url),
        'Links_in_tags': extract_Links_in_tags(url),
        'SFH': extract_SFH(url),
        'Submitting_to_email': extract_Submitting_to_email(url),
        'Abnormal_URL': extract_Abnormal_URL(url),
        'Redirect': extract_Redirect(url),
        'on_mouseover': extract_on_mouseover(url),
        'RightClick': extract_RightClick(url),
        'popUpWidnow': extract_popUpWidnow(url),
        'Iframe': extract_Iframe(url),
        'age_of_domain': extract_age_of_domain(url),
        'DNSRecord': extract_DNSRecord(url),
        'web_traffic': extract_web_traffic(url),
        'Page_Rank': extract_Page_Rank(url),
        'Google_Index': extract_Google_Index(url),
        'Links_pointing_to_page': extract_Links_pointing_to_page(url),
        'Statistical_report': extract_Statistical_report(url),
        # Only include this if your model was trained with it
        # 'Impersonating_Brand': extract_Impersonating_Brand(url),
    }
    return pd.DataFrame([features])

def prepare_features(url, feature_columns):
    df = extract_features(url)
    for col in feature_columns:
        if col not in df.columns:
            df[col] = -1   # default safe value
    df = df[feature_columns]  # reorder
    return df

def extract_Shortining_Service(url):
    shortening_services = ["bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly"]
    return 1 if any(service in url for service in shortening_services) else -1

if __name__ == "__main__":
    test_url = "http://example.com"
    df = extract_features(test_url)
    print("Extracted features (DataFrame):")
    print(df.head())

    # Example usage of prepare_features:
    feature_cols = df.columns.tolist()
    prepared_df = prepare_features(test_url, feature_cols)
    print("\nPrepared features (aligned with training columns):")
    print(prepared_df.head())


