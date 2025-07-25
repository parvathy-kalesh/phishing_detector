import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
import socket
import datetime
import pandas as pd

def extract_having_IP_Address(url):
    domain = urllib.parse.urlparse(url).netloc
    # Remove port if present
    domain = domain.split(':')[0]

    # Regex pattern for IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

    # Simple check for IPv4
    if re.match(ipv4_pattern, domain):
        # Check each segment is between 0 and 255
        parts = domain.split('.')
        for part in parts:
            if int(part) < 0 or int(part) > 255:
                return -1
        return 1
    
    # (Optional) Add IPv6 detection here if needed

    return -1

def extract_URL_Length(url):
    length = len(url)
    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    else:
        return -1



def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except:
        return False


def extract_Shortining_Service(url):
    shortening_services = ["bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly"]
    result = 1 if any(service in url for service in shortening_services) else -1
    print(f"Shortining_Service feature: {result} for URL: {url}")
    return result



def extract_having_At_Symbol(url):
    return 1 if '@' in url else -1

def extract_double_slash_redirecting(url):
    pos = url.find('//', 7)  # skip protocol
    return 1 if pos != -1 else -1

def extract_Prefix_Suffix(url):
    domain = urllib.parse.urlparse(url).netloc
    return 1 if '-' in domain else -1

def extract_having_Sub_Domain(url):
    domain = urllib.parse.urlparse(url).netloc
    dots = domain.count('.')
    if dots == 1:
        return -1
    elif dots == 2:
        return 0
    else:
        return 1

def extract_SSLfinal_State(url):
    try:
        domain = urllib.parse.urlparse(url).netloc
        import ssl, socket
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            notAfter = cert['notAfter']
            expire_date = datetime.datetime.strptime(notAfter, '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.datetime.utcnow()).days
            if days_left > 365:
                return 1
            elif 0 < days_left <= 365:
                return 0
            else:
                return -1
    except Exception:
        return -1

def extract_Domain_registeration_length(url):
    return 1

def extract_Favicon(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        favicon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        if favicon:
            href = favicon.get('href', '')
            domain = urllib.parse.urlparse(url).netloc
            if domain in href or href.startswith('/'):
                return 1
            else:
                return -1
        return -1
    except:
        return -1

def extract_port(url):
    domain = urllib.parse.urlparse(url).netloc
    if ':' in domain:
        port = int(domain.split(':')[1])
        if port == 80 or port == 443:
            return -1
        else:
            return 1
    return -1

def extract_HTTPS_token(url):
    domain = urllib.parse.urlparse(url).netloc
    return 1 if 'https' in domain else -1

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
            return 1
        ratio = external / total
        if ratio < 0.22:
            return 1
        elif 0.22 <= ratio <= 0.61:
            return 0
        else:
            return -1
    except:
        return -1

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
            return 1
        ratio = external / total
        if ratio < 0.31:
            return 1
        elif 0.31 <= ratio <= 0.67:
            return 0
        else:
            return -1
    except:
        return -1

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
            return 1
        ratio = external / total
        if ratio < 0.17:
            return 1
        elif 0.17 <= ratio <= 0.81:
            return 0
        else:
            return -1
    except:
        return -1

def extract_SFH(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            return 1
        domain = urllib.parse.urlparse(url).netloc
        for form in forms:
            action = form.get('action')
            if not action or action == "" or action.lower().startswith("javascript"):
                return -1
            action_domain = urllib.parse.urlparse(action).netloc
            if action_domain != "" and action_domain != domain:
                return 0
        return 1
    except:
        return -1

def extract_Submitting_to_email(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if 'mailto:' in r.text else -1
    except:
        return -1

def extract_Abnormal_URL(url):
    return -1

def extract_Redirect(url):
    try:
        r = requests.head(url, allow_redirects=True, timeout=5)
        return 1 if len(r.history) > 1 else 0
    except:
        return 0

def extract_on_mouseover(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "onmouseover" in r.text.lower() else -1
    except:
        return -1

def extract_RightClick(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "event.button==2" in r.text else -1
    except:
        return -1

def extract_popUpWidnow(url):
    try:
        r = requests.get(url, timeout=5)
        return 1 if "alert(" in r.text else -1
    except:
        return -1

def extract_Iframe(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, 'html.parser')
        return 1 if soup.find('iframe') else -1
    except:
        return -1

def extract_age_of_domain(url):
    return -1

def extract_DNSRecord(url):
    domain = urllib.parse.urlparse(url).netloc
    try:
        socket.gethostbyname(domain)
        return 1
    except:
        return -1

def extract_Impersonating_Brand(url):
    fake_brands = ['paypal', 'apple', 'google', 'gmail', 'facebook', 'amazon', 'microsoft', 'netflix', 'bankofamerica', 'ebay']
    suspicious_keywords = ['support', 'account', 'secure', 'login', 'update', 'verify']
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()  # full domain with subdomains

    for brand in fake_brands:
        if brand in domain:
            for keyword in suspicious_keywords:
                if keyword in domain:
                    # Also consider suspicious TLDs or just flag
                    return 1  # suspicious
            # If brand in domain but no suspicious keywords, still suspicious enough for phishing
            return 1
    return -1




def extract_web_traffic(url):
    return -1

def extract_Page_Rank(url):
    return -1

def extract_Google_Index(url):
    return -1

def extract_Links_pointing_to_page(url):
    return -1

def extract_Statistical_report(url):
    return -1

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
        'Impersonating_Brand':  extract_Impersonating_Brand(url),

    }
    return pd.DataFrame([features])

def prepare_features(url, feature_columns):
    df = extract_features(url)
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0  # or -1 if your dataset uses that
    df = df[feature_columns]
    return df


def extract_Shortining_Service(url):
    shortening_services = ["bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly"]
    return 1 if any(service in url for service in shortening_services) else -1


if __name__ == "__main__":
    test_url = "http://example.com"
    df = extract_features(test_url)
    print(type(df))
    print(df.head())

    # Example usage of prepare_features:
    feature_cols = df.columns.tolist()
    prepared_df = prepare_features(test_url, feature_cols)
    print(prepared_df.head())



