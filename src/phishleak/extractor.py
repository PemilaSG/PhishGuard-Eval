import re
from typing import Dict, Optional
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:
    tldextract = None

class URLEntityExtractor:
    """Extracts structural entities (subdomains, eTLD+1 domain, TLD, IP status, brand keywords)."""
    
    COMMON_BRANDS = [
        "paypal", "microsoft", "apple", "google", "amazon", "netflix",
        "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
        "linkedin", "dropbox", "docusign", "usps", "dhl", "fedex"
    ]
    
    @classmethod
    def extract_entities(cls, url: str) -> Dict[str, Optional[str]]:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0].lower()
        
        is_ip = cls._is_ip_address(hostname)
        
        etld_plus_one = None
        subdomain = None
        tld = None
        
        if not is_ip and hostname:
            if tldextract:
                ext = tldextract.extract(url)
                etld_plus_one = ext.registered_domain if ext.registered_domain else hostname
                subdomain = ext.subdomain if ext.subdomain else None
                tld = ext.suffix if ext.suffix else None
            else:
                parts = hostname.split('.')
                etld_plus_one = '.'.join(parts[-2:]) if len(parts) >= 2 else hostname
                subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else None
                tld = parts[-1] if parts else None

        detected_brand = cls._detect_brand_keyword(url)
        
        return {
            "raw_url": url,
            "hostname": hostname,
            "is_ip": is_ip,
            "etld_plus_one": etld_plus_one or hostname,
            "subdomain": subdomain,
            "tld": tld,
            "brand_keyword": detected_brand
        }
        
    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, hostname))
        
    @classmethod
    def _detect_brand_keyword(cls, url: str) -> Optional[str]:
        url_lower = url.lower()
        for brand in cls.COMMON_BRANDS:
            if brand in url_lower:
                return brand
        return None
