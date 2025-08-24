import re

def is_phishing(input_text):
    """
    Basic heuristic phishing detector for URLs/emails.
    Checks suspicious patterns like IP-based URLs, unusual domains, or known phishing keywords.
    """
    phishing_keywords = ['login', 'verify', 'account', 'update', 'security', 'bank', 'confirm']
    # Regex to detect IP address URLs
    ip_url_pattern = re.compile(r'http[s]?://(\d{1,3}\.){3}\d{1,3}')
    domain_pattern = re.compile(r'https?://([a-zA-Z0-9.-]+)')
    
    if ip_url_pattern.search(input_text):
        return True
    
    domains = domain_pattern.findall(input_text)
    for domain in domains:
        if any(keyword in domain.lower() for keyword in phishing_keywords):
            return True
    
    if any(keyword in input_text.lower() for keyword in phishing_keywords):
        return True

    return False
