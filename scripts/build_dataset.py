"""
build_dataset.py
================
Merges phishing (URLhaus + OpenPhish) and legitimate (Tranco) URLs,
extracts 21 lexical/structural features per URL, and writes:
  data/processed/dataset.csv    — labelled feature matrix
  data/processed/entities.csv   — raw entity metadata (for splitting)

Label: 1 = phishing, 0 = legitimate
"""

import os, re, csv, sys, io, math
from urllib.parse import urlparse

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

try:
    import tldextract
    import pandas as pd
    from tqdm import tqdm
except ImportError:
    sys.exit("[ERROR] pip install tldextract pandas tqdm")

ROOT       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW        = os.path.join(ROOT, "data", "raw")
PROCESSED  = os.path.join(ROOT, "data", "processed")
os.makedirs(PROCESSED, exist_ok=True)

TRANCO_PATH    = os.path.join(RAW, "tranco_top1m.csv")
URLHAUS_PATH   = os.path.join(RAW, "urlhaus_full.csv")
OPENPHISH_PATH = os.path.join(RAW, "openphish_feed.txt")

BRAND_KEYWORDS = [
    "paypal","microsoft","apple","google","amazon","netflix","facebook",
    "instagram","chase","wellsfargo","bankofamerica","linkedin","dropbox",
    "docusign","usps","dhl","fedex","ebay","twitter","yahoo","outlook",
    "office365","steam","coinbase","binance","blockchain","metamask","spotify"
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

def is_ip(hostname: str) -> bool:
    return bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))

def extract_features(url: str, label: int) -> dict | None:
    try:
        url = url.strip()
        if not re.match(r'^[a-zA-Z]+://', url):
            url = "http://" + url
        parsed  = urlparse(url)
        host    = parsed.netloc.split(":")[0].lower()
        path    = parsed.path
        ext     = tldextract.extract(url)
        etld1   = ext.registered_domain.lower() if ext.registered_domain else host
        subdomain = ext.subdomain.lower() if ext.subdomain else ""
        full_url  = url.lower()

        return {
            "url":               url,
            "label":             label,
            "etld_plus_one":     etld1,
            "subdomain":         subdomain,
            "hostname":          host,
            "is_ip":             int(is_ip(host)),
            "url_length":        len(url),
            "hostname_length":   len(host),
            "path_length":       len(path),
            "num_dots":          url.count("."),
            "num_hyphens":       host.count("-"),
            "num_underscores":   url.count("_"),
            "num_digits":        sum(c.isdigit() for c in host),
            "num_subdomains":    subdomain.count(".") + 1 if subdomain else 0,
            "has_https":         int(parsed.scheme == "https"),
            "has_at_symbol":     int("@" in url),
            "has_double_slash":  int("//" in path),
            "has_hex_encoding":  int("%" in url),
            "tld_length":        len(ext.suffix) if ext.suffix else 0,
            "path_depth":        path.count("/"),
            "url_entropy":       round(shannon_entropy(host), 4),
            "has_brand_keyword": int(any(b in full_url for b in BRAND_KEYWORDS)),
            "brand_keyword":     next((b for b in BRAND_KEYWORDS if b in full_url), ""),
            "query_length":      len(parsed.query),
            "num_special_chars": sum(1 for c in url if c in "-_=&?%@#~"),
        }
    except Exception:
        return None

# ── Loaders ──────────────────────────────────────────────────────────────────

def load_phishing():
    urls = []
    with open(URLHAUS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"): continue
            if len(row) >= 3 and row[2].strip('"').startswith("http"):
                urls.append(row[2].strip('"'))
    with open(OPENPHISH_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            u = line.strip()
            if u.startswith("http"):
                urls.append(u)
    return list(set(urls))          # deduplicate

def load_legit(sample_size=35000):
    """Sample legitimate domains to roughly balance the dataset."""
    domains = []
    with open(TRANCO_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                domains.append("http://" + row[1].strip().lower())
            if len(domains) >= sample_size:
                break
    return domains

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=== Building Labelled Dataset ===\n")

    print("Loading phishing URLs...")
    phishing = load_phishing()
    print(f"  Phishing: {len(phishing):,} unique URLs")

    print("Loading legitimate URLs...")
    legit = load_legit(sample_size=len(phishing))   # balanced
    print(f"  Legitimate: {len(legit):,} URLs\n")

    all_urls = [(u, 1) for u in phishing] + [(u, 0) for u in legit]

    print(f"Extracting features for {len(all_urls):,} URLs...")
    rows = []
    for url, lbl in tqdm(all_urls, unit="url"):
        feat = extract_features(url, lbl)
        if feat:
            rows.append(feat)

    df = pd.DataFrame(rows)
    out_path = os.path.join(PROCESSED, "dataset.csv")
    df.to_csv(out_path, index=False)
    print(f"\n[OK] Saved {len(df):,} rows -> {out_path}")
    print(f"     Phishing: {df['label'].sum():,}  |  Legitimate: {(df['label']==0).sum():,}")
    print(f"     Features: {len(df.columns)-4} lexical features + metadata columns")

if __name__ == "__main__":
    main()
