# PhishLeak: Multi-Tiered Infrastructure Leakage Audit & Evaluation Framework for Phishing URL Detection

## Proposed Research Title
**Multi-Tiered Infrastructure Leakage in Machine Learning-Based Phishing URL Detection: A Standardized Evaluation Framework**

---

## Abstract / Core Concept
Phishing URL detection models report artificially inflated accuracy due to unrecognized data leakage across training and evaluation sets. Existing studies focus only on simple single-domain ($eTLD+1$) overlap. This project introduces **PhishLeak**, a standardized evaluation framework that audits and controls for **4-tiered infrastructure leakage** (exact duplicates, domain overlap, subdomain/brand keyword clustering, and network IP/ASN infrastructure).

---

## Key Research Questions (RQs)
- **RQ1**: How severe is multi-tiered infrastructure leakage across standard public phishing datasets?
- **RQ2**: What is the true generalization degradation ($\Delta F1$, $\Delta FPR$) when evaluating models under strict Tier-1 to Tier-4 disjoint splits?
- **RQ3**: Which ML/DL model families (Handcrafted Features, XGBoost, Character CNNs, Transformers) are most vulnerable to shortcut domain memorization?
- **RQ4**: Can an automated group-stratified splitting algorithm eliminate multi-tiered leakage while preserving dataset class balance?

---

## Documentation Links
- [Research Gap Analysis](file:///D:/projects/Machine%20Learning-Based%20Phishing%20URL%20Detection/docs/research_gap_analysis.md)
- [Framework Technical Specification](file:///D:/projects/Machine%20Learning-Based%20Phishing%20URL%20Detection/docs/framework_specification.md)
- [Comparative Literature Matrix](file:///D:/projects/Machine%20Learning-Based%20Phishing%20URL%20Detection/literature/literature_matrix.md)

---

## Project Structure
- `docs/`: Architectural specifications and research gap analysis.
- `literature/`: Comparative literature matrix and notes.
- `src/phishleak/`: Core Python framework package.
- `data/`: Dataset storage directory.
- `experiments/`: Benchmark and experiment scripts.
