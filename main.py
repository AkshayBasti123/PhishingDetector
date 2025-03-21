import re
from urllib.parse import urlparse

# List of suspicious TLDs (commonly used in phishing)
suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.biz', '.info']

# Function to check for phishing patterns
def is_phishing_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Rule 1: Check for multiple hyphens (e.g., pay-pal-secure-login.com)
    if domain.count('-') > 2:
        return "⚠️ Suspicious: Too many hyphens in domain!"

    # Rule 2: Check for 'http' instead of 'https' (if applicable)
    if parsed_url.scheme == "http":
        return "⚠️ Warning: Not using HTTPS!"

    # Rule 3: Check if domain has 'login', 'verify', 'secure' (common phishing keywords)
    phishing_keywords = ["login", "secure", "verify", "account", "banking"]
    if any(keyword in domain.lower() for keyword in phishing_keywords):
        return "🚨 Phishing Alert: Domain contains suspicious keywords!"

    # Rule 4: Check for suspicious TLDs
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        return "⚠️ Suspicious: Domain uses a high-risk TLD!"

    # Rule 5: Check for @ symbol in URL (phishing trick)
    if '@' in domain:
        return "🚨 Phishing Alert: '@' symbol detected in URL!"

    return "✅ Safe URL (No obvious phishing patterns detected)"

# Example Usage
if __name__ == "__main__":
    url = input("Enter a URL to check: ")
    print(is_phishing_url(url))
