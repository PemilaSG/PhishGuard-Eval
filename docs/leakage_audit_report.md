# Multi-Tiered Leakage Audit Report
> **Framework**: PhishGuard-Eval | **Step**: RQ1 — Leakage Audit  
> **Datasets**: Tranco Top-1M (Legitimate) · URLhaus (Phishing) · OpenPhish (Phishing)

---

## Tier 1: Exact Canonical URL Duplication

| Metric | Value |
|---|---|
| Phishing URLs (raw) | 33,228 |
| Phishing URLs (unique after canonicalization) | 33,224 |
| Internal Duplicates | 4 (0.01%) |
| Cross-Set URL Overlaps (Phishing ∩ Legit) | 0 (0.0%) |

## Tier 2: Registered Domain (eTLD+1) Overlap

| Metric | Value |
|---|---|
| Unique Phishing Registered Domains | 7,072 |
| Unique Legitimate Registered Domains | 999,999 |
| Overlapping Domains | 102 (1.44%) |
| Sample Overlapping Domains | `4everland.app`, `aliyuncs.com`, `amazonaws.com`, `azionedge.net`, `azurefd.net` |

## Tier 3: Subdomain & Brand-Keyword Clustering

| Metric | Value |
|---|---|
| Phishing URLs containing brand keyword | 486 |
| Legitimate domains containing brand keyword | 2,066 |
| Shared brand keywords (leakage risk) | 24 |
| Multi-level subdomain phishing URLs | 115 |
| Shared brand keywords list | `amazon`, `apple`, `binance`, `blockchain`, `chase`, `coinbase`, `dhl`, `docusign`, `dropbox`, `ebay`, `facebook`, `google`, `instagram`, `linkedin`, `metamask`, `microsoft`, `netflix`, `office365`, `outlook`, `paypal`, `spotify`, `steam`, `twitter`, `yahoo` |

### Brand Keyword Co-occurrence (Phishing ↔ Legitimate)

| Brand | Phishing Hits | Legitimate Hits |
|---|---|---|
| `google` | 170 | 452 |
| `dropbox` | 84 | 21 |
| `amazon` | 34 | 205 |
| `apple` | 29 | 240 |
| `steam` | 21 | 201 |
| `linkedin` | 21 | 9 |
| `instagram` | 15 | 50 |
| `blockchain` | 15 | 43 |
| `metamask` | 14 | 1 |
| `netflix` | 13 | 51 |
| `facebook` | 13 | 57 |
| `spotify` | 11 | 34 |
| `twitter` | 10 | 32 |
| `microsoft` | 10 | 96 |
| `chase` | 7 | 78 |
| `binance` | 7 | 19 |
| `docusign` | 3 | 3 |
| `outlook` | 2 | 47 |
| `dhl` | 2 | 43 |
| `ebay` | 1 | 135 |
| `coinbase` | 1 | 6 |
| `yahoo` | 1 | 63 |
| `paypal` | 1 | 145 |
| `office365` | 1 | 10 |

## Tier 4: Network / IP Infrastructure Overlap

| Metric | Value |
|---|---|
| Phishing URLs using raw IP addresses | 16,038 (48.27%) |
| Legitimate URLs using raw IP addresses | 0 (0.0%) |
| Unique phishing IPs | 6,496 |
| Unique legitimate IPs | 0 |
| Shared IP Overlap Count | 0 |

---

## Dataset Hygiene Score

$$\text{Hygiene Score} = 0.7807 \ / \ 1.0$$

| Score Range | Rating |
|---|---|
| 0.90 - 1.00 | EXCELLENT - very low leakage risk |
| 0.75 - 0.89 | GOOD - moderate leakage, monitor closely |
| 0.50 - 0.74 | POOR - significant leakage, domain-disjoint split required |
| 0.00 - 0.49 | CRITICAL - severe leakage, baseline metrics are unreliable |

> **This dataset combination scored: `0.7807`**
