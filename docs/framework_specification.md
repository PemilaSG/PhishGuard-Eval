# Technical Specification: Multi-Tiered Phishing URL Leakage Audit & Evaluation Framework

## Overview
`PhishLeak` is an open-source Python evaluation framework designed to detect multi-tiered infrastructure leakage in phishing URL datasets and generate leakage-proof, domain-disjoint train/validation/test splits.

---

## Modular Architecture

```
src/phishleak/
├── __init__.py
├── canonicalizer.py    # URL normalization (protocols, ports, parameters, casing)
├── extractor.py        # Feature & entity extraction (eTLD+1, subdomains, IP/ASN, brand keywords)
├── auditor.py          # Multi-tiered leakage scoring & overlap detection
├── splitter.py         # Automated leakage-resistant split generator (Tiers 1-4)
├── models/             # Baseline models (RandomForest, XGBoost, Char-CNN, BERT/RoBERTa)
└── metrics.py          # Generalization delta metrics (ΔF1, ΔFPR, Out-of-Domain Precision)
```

---

## Key Modules & Responsibilities

### 1. `canonicalizer.py`
- Protocol stripping (`http://` vs `https://`).
- Lowercasing hostnames while preserving query param case where relevant.
- Query parameter sorting and anchor removal.
- IP vs domain classification.

### 2. `extractor.py`
- `tldextract` integration for exact `subdomain`, `domain`, and `suffix` extraction.
- Brand keyword regex parser (extracting target brands like `paypal`, `microsoft`, `apple`).
- IP lookup & ASN resolving (optional online enrichment / offline dataset mapping).

### 3. `auditor.py`
- Computes **Jaccard Domain Overlap Coefficient** across splits.
- Calculates **Overlap Ratios** for Tiers 1 through 4.
- Generates a **Dataset Hygiene Score** ($0.0 - 1.0$).

### 4. `splitter.py`
- Implements `MultiTierDisjointSplitter(tier=1|2|3|4, test_size=0.2, random_state=42)`.
- Ensures zero host/domain/brand overlap between train, val, and test sets.
- Maintains positive/negative class ratio balance using group-stratified partitioning.
