"""
Multi-Tiered Infrastructure Leakage Audit - RQ1
================================================
Audits leakage between phishing (URLhaus + OpenPhish) and legitimate (Tranco) datasets
across four progressively stricter infrastructure tiers:

  Tier 1  — Exact canonical URL duplication
  Tier 2  — Registered domain (eTLD+1) overlap
  Tier 3  — Subdomain & brand-keyword clustering
  Tier 4  — Network-level IP host overlap

Output  : Console report + docs/leakage_audit_report.md
"""

import os
import re
import sys
import csv
import json
import socket
import io

# Force UTF-8 output on Windows to avoid CP1252 codec errors
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from urllib.parse import urlparse, urlunparse
from collections import defaultdict

# ─────────────────────────── dependency check ───────────────────────────────
try:
    import tldextract
    from tabulate import tabulate
except ImportError:
    sys.exit("[ERROR] Install missing packages:  pip install tldextract tabulate")

# ─────────────────────────── paths ──────────────────────────────────────────
ROOT_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR    = os.path.join(ROOT_DIR, "data", "raw")
REPORT_DIR = os.path.join(ROOT_DIR, "docs")
REPORT_PATH = os.path.join(REPORT_DIR, "leakage_audit_report.md")
JSON_PATH   = os.path.join(REPORT_DIR, "leakage_audit_results.json")

TRANCO_PATH    = os.path.join(RAW_DIR, "tranco_top1m.csv")
URLHAUS_PATH   = os.path.join(RAW_DIR, "urlhaus_full.csv")
OPENPHISH_PATH = os.path.join(RAW_DIR, "openphish_feed.txt")

# Brand keywords for Tier-3 analysis
BRAND_KEYWORDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "linkedin", "dropbox", "docusign", "usps", "dhl", "fedex",
    "ebay", "twitter", "yahoo", "outlook", "office365", "steam",
    "coinbase", "binance", "blockchain", "metamask", "spotify"
]


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — DATA LOADERS
# ═══════════════════════════════════════════════════════════════════════════

def canonicalize_url(url: str) -> str:
    """Normalize a URL for exact-match comparison (Tier-1)."""
    url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', url):
        url = 'http://' + url
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    # Remove default ports
    if netloc.endswith(':80') and scheme == 'http':
        netloc = netloc[:-3]
    elif netloc.endswith(':443') and scheme == 'https':
        netloc = netloc[:-4]
    path = parsed.path.rstrip('/')
    canonical = urlunparse((scheme, netloc, path, '', parsed.query, ''))
    return canonical


def extract_entities(url: str) -> dict:
    """Extract domain entities from a URL using tldextract."""
    ext        = tldextract.extract(url)
    hostname   = urlparse(url if '://' in url else 'http://' + url).netloc.split(':')[0].lower()
    is_ip      = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
    etld1      = ext.registered_domain.lower() if ext.registered_domain else hostname
    subdomain  = ext.subdomain.lower()         if ext.subdomain          else ""
    tld        = ext.suffix.lower()            if ext.suffix             else ""
    brand      = next((b for b in BRAND_KEYWORDS if b in url.lower()), None)
    return {
        "raw_url":       url,
        "canonical":     canonicalize_url(url),
        "hostname":      hostname,
        "is_ip":         is_ip,
        "etld_plus_one": etld1,
        "subdomain":     subdomain,
        "tld":           tld,
        "brand":         brand,
    }


def load_phishing_urls() -> list:
    """Load and merge phishing URLs from URLhaus and OpenPhish."""
    urls = []

    # URLhaus: skip comment lines, parse CSV column index 2
    print("  Loading URLhaus...")
    with open(URLHAUS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) >= 3:
                raw = row[2].strip().strip('"')
                if raw.startswith("http"):
                    urls.append(raw)

    # OpenPhish: one URL per line
    print("  Loading OpenPhish...")
    with open(OPENPHISH_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            raw = line.strip()
            if raw.startswith("http"):
                urls.append(raw)

    print(f"  Total phishing URLs loaded: {len(urls):,}")
    return urls


def load_legitimate_domains() -> list:
    """Load Tranco Top-1M domain list and convert to URLs."""
    domains = []
    print("  Loading Tranco Top 1M...")
    with open(TRANCO_PATH, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                domain = row[1].strip().lower()
                if domain:
                    domains.append("http://" + domain)
    print(f"  Total legitimate domains loaded: {len(domains):,}")
    return domains


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — TIER AUDITS
# ═══════════════════════════════════════════════════════════════════════════

def audit_tier1(phishing_urls: list, legit_urls: list) -> dict:
    """Tier-1: Exact canonical URL duplication."""
    print("\n[Tier 1] Computing exact canonical URL overlap...")
    phish_canonical = {canonicalize_url(u) for u in phishing_urls}
    legit_canonical = {canonicalize_url(u) for u in legit_urls}

    # Internal duplicates (within phishing set)
    phishing_raw_count    = len(phishing_urls)
    phishing_unique_count = len(phish_canonical)
    internal_dupes        = phishing_raw_count - phishing_unique_count

    # Cross-set overlap
    cross_overlap = phish_canonical & legit_canonical
    cross_count   = len(cross_overlap)

    return {
        "tier": 1,
        "description": "Exact Canonical URL Duplication",
        "phishing_raw_count":    phishing_raw_count,
        "phishing_unique_count": phishing_unique_count,
        "internal_duplicates":   internal_dupes,
        "internal_dup_rate_pct": round(internal_dupes / phishing_raw_count * 100, 2),
        "legit_unique_count":    len(legit_canonical),
        "cross_overlap_count":   cross_count,
        "cross_overlap_pct":     round(cross_count / phishing_unique_count * 100, 4) if phishing_unique_count else 0,
        "sample_overlaps":       list(cross_overlap)[:5],
    }


def audit_tier2(phishing_entities: list, legit_entities: list) -> dict:
    """Tier-2: Registered domain (eTLD+1) overlap."""
    print("[Tier 2] Computing eTLD+1 registered domain overlap...")
    phish_domains = {e["etld_plus_one"] for e in phishing_entities if e["etld_plus_one"]}
    legit_domains  = {e["etld_plus_one"] for e in legit_entities   if e["etld_plus_one"]}

    overlap   = phish_domains & legit_domains
    n_overlap = len(overlap)

    return {
        "tier": 2,
        "description": "Registered Domain (eTLD+1) Overlap",
        "phishing_unique_domains": len(phish_domains),
        "legit_unique_domains":    len(legit_domains),
        "overlapping_domains":     n_overlap,
        "phish_domain_overlap_pct": round(n_overlap / len(phish_domains) * 100, 2) if phish_domains else 0,
        "sample_overlaps": sorted(list(overlap))[:10],
    }


def audit_tier3(phishing_entities: list, legit_entities: list) -> dict:
    """Tier-3: Subdomain pattern & brand-keyword clustering."""
    print("[Tier 3] Computing subdomain & brand-keyword clustering overlap...")

    # Brand keyword counts
    phish_brands = defaultdict(int)
    for e in phishing_entities:
        if e["brand"]:
            phish_brands[e["brand"]] += 1

    legit_brands = defaultdict(int)
    for e in legit_entities:
        if e["brand"]:
            legit_brands[e["brand"]] += 1

    shared_brands    = set(phish_brands.keys()) & set(legit_brands.keys())
    phish_brand_total = sum(phish_brands.values())

    # Subdomain structure: count multi-level (high-suspicion) subdomains
    multi_level_subdomains = [
        e for e in phishing_entities
        if e["subdomain"] and e["subdomain"].count('.') >= 1
    ]

    # Phishing domains targeting brand keywords also present in legit set
    brand_overlap_rows = [
        {"brand": b, "phishing_count": phish_brands[b], "legit_count": legit_brands[b]}
        for b in sorted(shared_brands, key=lambda x: -phish_brands[x])
    ]

    return {
        "tier": 3,
        "description": "Subdomain & Brand-Keyword Clustering",
        "phishing_brand_keyword_hits":  phish_brand_total,
        "phishing_urls_with_brand":     len([e for e in phishing_entities if e["brand"]]),
        "legit_urls_with_brand":        len([e for e in legit_entities    if e["brand"]]),
        "shared_brand_keywords":        len(shared_brands),
        "shared_brand_list":            sorted(list(shared_brands)),
        "brand_overlap_detail":         brand_overlap_rows,
        "phishing_multi_level_subdomains": len(multi_level_subdomains),
        "sample_multi_level_subdomains": [e["raw_url"] for e in multi_level_subdomains[:5]],
    }


def audit_tier4(phishing_entities: list, legit_entities: list) -> dict:
    """
    Tier-4: Network-level IP host overlap.
    For URLs using raw IP addresses: identify IPs that appear in both phishing
    and legitimate datasets. Also computes how many phishing URLs bypass DNS
    (i.e., use raw IPs directly, which is itself a phishing signal).
    DNS-based cross-resolution is skipped for speed.
    """
    print("[Tier 4] Computing network/IP infrastructure overlap...")

    phish_ips = {e["hostname"] for e in phishing_entities if e["is_ip"]}
    legit_ips  = {e["hostname"] for e in legit_entities   if e["is_ip"]}

    ip_overlap     = phish_ips & legit_ips
    phish_ip_urls  = [e for e in phishing_entities if e["is_ip"]]
    legit_ip_urls  = [e for e in legit_entities    if e["is_ip"]]

    phish_total = len(phishing_entities)
    legit_total = len(legit_entities)

    return {
        "tier": 4,
        "description": "Network / IP Infrastructure Overlap",
        "phishing_total_urls":       phish_total,
        "phishing_raw_ip_url_count": len(phish_ip_urls),
        "phishing_raw_ip_pct":       round(len(phish_ip_urls) / phish_total * 100, 2) if phish_total else 0,
        "legit_raw_ip_url_count":    len(legit_ip_urls),
        "legit_raw_ip_pct":          round(len(legit_ip_urls) / legit_total * 100, 2) if legit_total else 0,
        "unique_phishing_ips":       len(phish_ips),
        "unique_legit_ips":          len(legit_ips),
        "ip_overlap_count":          len(ip_overlap),
        "sample_phishing_ips":       sorted(list(phish_ips))[:5],
        "sample_ip_overlaps":        sorted(list(ip_overlap))[:5],
    }


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def compute_hygiene_score(t1: dict, t2: dict, t3: dict, t4: dict) -> float:
    """
    Dataset Hygiene Score (0.0 = severely leaky, 1.0 = perfectly clean).
    Weighted penalty across the four tiers.
    """
    # Penalties (0 to 1 per tier, weighted)
    p1 = min(t1["internal_dup_rate_pct"] / 100, 1.0)      # internal dupe rate
    p2 = min(t2["phish_domain_overlap_pct"] / 100, 1.0)    # domain overlap
    p3 = min(t3["shared_brand_keywords"] / len(BRAND_KEYWORDS), 1.0)  # brand leakage ratio
    p4 = min(t4["ip_overlap_count"] / max(t4["unique_phishing_ips"], 1), 1.0)

    weights = [0.20, 0.35, 0.25, 0.20]   # Tier 1-4 weights
    penalty = sum(w * p for w, p in zip(weights, [p1, p2, p3, p4]))
    return round(1.0 - penalty, 4)


def print_console_report(t1, t2, t3, t4, score):
    sep = "=" * 66
    print(f"\n{sep}")
    print("  MULTI-TIERED LEAKAGE AUDIT REPORT — PhishGuard-Eval")
    print(sep)

    print("\n── TIER 1: Exact Canonical URL Duplication ──")
    rows1 = [
        ["Phishing URLs (raw)",         f"{t1['phishing_raw_count']:,}"],
        ["Phishing URLs (unique)",       f"{t1['phishing_unique_count']:,}"],
        ["Internal Duplicates",          f"{t1['internal_duplicates']:,} ({t1['internal_dup_rate_pct']}%)"],
        ["Cross-Set URL Overlaps",       f"{t1['cross_overlap_count']:,} ({t1['cross_overlap_pct']}%)"],
    ]
    print(tabulate(rows1, tablefmt="simple"))

    print("\n── TIER 2: Registered Domain (eTLD+1) Overlap ──")
    rows2 = [
        ["Unique Phishing Domains",      f"{t2['phishing_unique_domains']:,}"],
        ["Unique Legitimate Domains",    f"{t2['legit_unique_domains']:,}"],
        ["Overlapping Domains",          f"{t2['overlapping_domains']:,} ({t2['phish_domain_overlap_pct']}%)"],
        ["Sample Overlapping Domains",   ", ".join(t2['sample_overlaps'][:5])],
    ]
    print(tabulate(rows2, tablefmt="simple"))

    print("\n── TIER 3: Subdomain & Brand-Keyword Clustering ──")
    rows3 = [
        ["Phishing URLs with Brand Keyword",    f"{t3['phishing_urls_with_brand']:,}"],
        ["Legit Domains with Brand Keyword",    f"{t3['legit_urls_with_brand']:,}"],
        ["Shared Brand Keywords (leakage risk)",f"{t3['shared_brand_keywords']}"],
        ["Multi-Level Subdomain Phishing URLs", f"{t3['phishing_multi_level_subdomains']:,}"],
        ["Shared Brand Keywords List",           ", ".join(t3['shared_brand_list'])],
    ]
    print(tabulate(rows3, tablefmt="simple"))

    if t3["brand_overlap_detail"]:
        print("\n  Brand Keyword Co-occurrence (Phishing ↔ Legitimate):")
        brand_table = [[r["brand"], r["phishing_count"], r["legit_count"]]
                       for r in t3["brand_overlap_detail"]]
        print(tabulate(brand_table, headers=["Brand", "Phishing Hits", "Legit Hits"], tablefmt="simple"))

    print("\n── TIER 4: Network / IP Infrastructure Overlap ──")
    rows4 = [
        ["Phishing URLs using raw IPs",  f"{t4['phishing_raw_ip_url_count']:,} ({t4['phishing_raw_ip_pct']}%)"],
        ["Legit URLs using raw IPs",     f"{t4['legit_raw_ip_url_count']:,} ({t4['legit_raw_ip_pct']}%)"],
        ["Unique Phishing IPs",          f"{t4['unique_phishing_ips']:,}"],
        ["Unique Legit IPs",             f"{t4['unique_legit_ips']:,}"],
        ["Shared IP Overlap Count",      f"{t4['ip_overlap_count']:,}"],
        ["Sample Phishing IPs",          ", ".join(t4['sample_phishing_ips'])],
    ]
    print(tabulate(rows4, tablefmt="simple"))

    print(f"\n{'─'*66}")
    print(f"  DATASET HYGIENE SCORE:  {score:.4f} / 1.0000")
    rating = (
        "EXCELLENT (very low leakage risk)" if score >= 0.90 else
        "GOOD      (moderate leakage, monitor closely)" if score >= 0.75 else
        "POOR      (significant leakage — domain-disjoint split required)" if score >= 0.50 else
        "CRITICAL  (severe leakage — baseline metrics are unreliable)"
    )
    print(f"  Rating   :  {rating}")
    print(f"{'─'*66}\n")


def write_markdown_report(t1, t2, t3, t4, score):
    md = []
    md.append("# Multi-Tiered Leakage Audit Report\n")
    md.append("> **Framework**: PhishGuard-Eval | **Step**: RQ1 — Leakage Audit  \n")
    md.append("> **Datasets**: Tranco Top-1M (Legitimate) · URLhaus (Phishing) · OpenPhish (Phishing)\n\n")
    md.append("---\n\n")

    # Tier 1
    md.append("## Tier 1: Exact Canonical URL Duplication\n\n")
    md.append("| Metric | Value |\n|---|---|\n")
    md.append(f"| Phishing URLs (raw) | {t1['phishing_raw_count']:,} |\n")
    md.append(f"| Phishing URLs (unique after canonicalization) | {t1['phishing_unique_count']:,} |\n")
    md.append(f"| Internal Duplicates | {t1['internal_duplicates']:,} ({t1['internal_dup_rate_pct']}%) |\n")
    md.append(f"| Cross-Set URL Overlaps (Phishing ∩ Legit) | {t1['cross_overlap_count']:,} ({t1['cross_overlap_pct']}%) |\n\n")

    # Tier 2
    md.append("## Tier 2: Registered Domain (eTLD+1) Overlap\n\n")
    md.append("| Metric | Value |\n|---|---|\n")
    md.append(f"| Unique Phishing Registered Domains | {t2['phishing_unique_domains']:,} |\n")
    md.append(f"| Unique Legitimate Registered Domains | {t2['legit_unique_domains']:,} |\n")
    md.append(f"| Overlapping Domains | {t2['overlapping_domains']:,} ({t2['phish_domain_overlap_pct']}%) |\n")
    md.append(f"| Sample Overlapping Domains | `{'`, `'.join(t2['sample_overlaps'][:5])}` |\n\n")

    # Tier 3
    md.append("## Tier 3: Subdomain & Brand-Keyword Clustering\n\n")
    md.append("| Metric | Value |\n|---|---|\n")
    md.append(f"| Phishing URLs containing brand keyword | {t3['phishing_urls_with_brand']:,} |\n")
    md.append(f"| Legitimate domains containing brand keyword | {t3['legit_urls_with_brand']:,} |\n")
    md.append(f"| Shared brand keywords (leakage risk) | {t3['shared_brand_keywords']} |\n")
    md.append(f"| Multi-level subdomain phishing URLs | {t3['phishing_multi_level_subdomains']:,} |\n")
    md.append(f"| Shared brand keywords list | `{'`, `'.join(t3['shared_brand_list'])}` |\n\n")

    if t3["brand_overlap_detail"]:
        md.append("### Brand Keyword Co-occurrence (Phishing ↔ Legitimate)\n\n")
        md.append("| Brand | Phishing Hits | Legitimate Hits |\n|---|---|---|\n")
        for r in t3["brand_overlap_detail"]:
            md.append(f"| `{r['brand']}` | {r['phishing_count']} | {r['legit_count']} |\n")
        md.append("\n")

    # Tier 4
    md.append("## Tier 4: Network / IP Infrastructure Overlap\n\n")
    md.append("| Metric | Value |\n|---|---|\n")
    md.append(f"| Phishing URLs using raw IP addresses | {t4['phishing_raw_ip_url_count']:,} ({t4['phishing_raw_ip_pct']}%) |\n")
    md.append(f"| Legitimate URLs using raw IP addresses | {t4['legit_raw_ip_url_count']:,} ({t4['legit_raw_ip_pct']}%) |\n")
    md.append(f"| Unique phishing IPs | {t4['unique_phishing_ips']:,} |\n")
    md.append(f"| Unique legitimate IPs | {t4['unique_legit_ips']:,} |\n")
    md.append(f"| Shared IP Overlap Count | {t4['ip_overlap_count']:,} |\n\n")

    # Hygiene Score
    md.append("---\n\n")
    md.append("## Dataset Hygiene Score\n\n")
    md.append(f"$$\\text{{Hygiene Score}} = {score:.4f} \\ / \\ 1.0$$\n\n")
    md.append("| Score Range | Rating |\n|---|---|\n")
    md.append("| 0.90 - 1.00 | EXCELLENT - very low leakage risk |\n")
    md.append("| 0.75 - 0.89 | GOOD - moderate leakage, monitor closely |\n")
    md.append("| 0.50 - 0.74 | POOR - significant leakage, domain-disjoint split required |\n")
    md.append("| 0.00 - 0.49 | CRITICAL - severe leakage, baseline metrics are unreliable |\n\n")
    md.append(f"> **This dataset combination scored: `{score:.4f}`**\n")

    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.writelines(md)
    print(f"  [OK] Markdown report saved -> {REPORT_PATH}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 66)
    print("  PhishGuard-Eval: Multi-Tiered Leakage Audit - RQ1")
    print("=" * 66 + "\n")

    # 1. Load datasets
    print("[Step 1/6] Loading datasets...")
    phishing_urls = load_phishing_urls()
    legit_urls    = load_legitimate_domains()

    # 2. Extract entities for all URLs
    print("\n[Step 2/6] Extracting URL entities (this may take a moment)...")
    phishing_entities = [extract_entities(u) for u in phishing_urls]
    legit_entities    = [extract_entities(u) for u in legit_urls]
    print(f"  Entities extracted — Phishing: {len(phishing_entities):,} | Legit: {len(legit_entities):,}")

    # 3. Run Tier audits
    print("\n[Step 3/6] Running Tier-1 audit...")
    t1 = audit_tier1(phishing_urls, legit_urls)

    print("[Step 4/6] Running Tier-2 audit...")
    t2 = audit_tier2(phishing_entities, legit_entities)

    print("[Step 5/6] Running Tier-3 audit...")
    t3 = audit_tier3(phishing_entities, legit_entities)

    print("[Step 6/6] Running Tier-4 audit...")
    t4 = audit_tier4(phishing_entities, legit_entities)

    # 4. Compute hygiene score
    score = compute_hygiene_score(t1, t2, t3, t4)

    # 5. Print and save reports
    print_console_report(t1, t2, t3, t4, score)

    print("  Saving reports...")
    write_markdown_report(t1, t2, t3, t4, score)

    results = {"tier_1": t1, "tier_2": t2, "tier_3": t3, "tier_4": t4, "hygiene_score": score}
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"  [OK] JSON results saved  -> {JSON_PATH}")
    print("\n  [DONE] Leakage audit complete.\n")


if __name__ == "__main__":
    main()
