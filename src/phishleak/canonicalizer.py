import re
from urllib.parse import urlparse, urlunparse

class URLCanonicalizer:
    """Standardizes URLs by normalizing scheme, hostname casing, default ports, and parameters."""
    
    @staticmethod
    def canonicalize(url: str) -> str:
        if not url:
            return ""
        
        url = url.strip()
        
        # Prepend scheme if missing for proper parsing
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
            
        parsed = urlparse(url)
        
        # Lowercase scheme and hostname
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove standard default ports
        if netloc.endswith(':80') and scheme == 'http':
            netloc = netloc[:-3]
        elif netloc.endswith(':443') and scheme == 'https':
            netloc = netloc[:-4]
            
        # Strip trailing slash from path if empty
        path = parsed.path
        if path == '/':
            path = ''
            
        # Reconstruct canonical URL without fragment anchors
        canonical = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ''))
        return canonical
