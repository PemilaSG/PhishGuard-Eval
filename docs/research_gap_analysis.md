# Confirmed Research Gap & Strategic Positioning

## Chosen Research Direction: Option A (Multi-Tiered Infrastructure Leakage & Automated Benchmark Framework)

### Confirmed Research Gap Statement
> *"While prior work (e.g., Rethinking Phishing Detection, 2025) identified basic single-domain ($eTLD+1$) leakage in public datasets, no standardized evaluation framework exists that accounts for **multi-tiered infrastructure leakage** (subdomain hierarchy, brand target clustering, IP/ASN infrastructure overlap) or provides **automated, zero-leakage split generators** for reproducible phishing detection benchmarks."*

---

## The 4 Tiers of Phishing Data Leakage

Standard papers either perform random splitting (0 control) or basic $eTLD+1$ domain splitting (Tier 2 control). Our framework introduces a comprehensive **4-Tier Leakage Hierarchy**:

```
+-------------------------------------------------------------------------------+
| Tier 1: Canonical URL Duplication                                            |
|   - Exact string matches, protocol variants (http/https), trailing slashes.  |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| Tier 2: Registered Domain (eTLD+1) Overlap                                    |
|   - Standard domain leakage (e.g., paypal-verify.com in train and test).      |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| Tier 3: Subdomain & Brand Keyword Clustering                                  |
|   - Brand-targeting keyword patterns across dynamic DNS providers             |
|     (e.g., paypal.login.duckdns.org vs paypal.security.ngrok.io).             |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
| Tier 4: Network & Hosting Infrastructure Overlap (IP / ASN / Host Provider)  |
|   - Shared hosting servers, fast-flux IP pools, and autonomous systems.      |
+-------------------------------------------------------------------------------+
```

---

## Research Questions (RQs)

* **RQ1 (Leakage Audit)**: How severe is multi-tiered infrastructure leakage across widely used phishing benchmark datasets (e.g., PhishTank, OpenPhish, Kaggle Phishing URLs, URLhaus)?
* **RQ2 (Performance Degradation)**: To what extent does model performance ($\Delta F1$, $\Delta FPR$) degrade when moving from Naive Random Splitting to Tier-1 $\rightarrow$ Tier-4 Disjoint Splitting?
* **RQ3 (Shortcut Learning)**: Which feature representations (Lexical TF-IDF, Handcrafted Features, Deep Learning Character CNNs, Transformer Embeddings) are most vulnerable to multi-tier infrastructure memorization?
* **RQ4 (Standardization Tool)**: Can an automated, open-source splitting generator eliminate multi-tiered leakage while preserving balanced class distributions?
