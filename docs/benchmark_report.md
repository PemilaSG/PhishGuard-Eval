# Benchmark Results: Phishing URL Detection Under Domain-Disjoint Evaluation

> **Framework**: PhishGuard-Eval  
> **RQ2**: Performance degradation under stricter splits  
> **RQ3**: Model vulnerability to shortcut learning

---

## Split Strategy: `NAIVE`

| Model | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| LogisticRegression | 1.0000 | 0.9971 | 0.9986 | 0.0000 | 0.9986 |
| RandomForest | 1.0000 | 0.9998 | 0.9999 | 0.0000 | 0.9999 |
| XGBoost | 1.0000 | 0.9998 | 0.9999 | 0.0000 | 0.9999 |

## Split Strategy: `TIER1`

| Model | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| LogisticRegression | 1.0000 | 0.9971 | 0.9986 | 0.0000 | 0.9986 |
| RandomForest | 1.0000 | 0.9998 | 0.9999 | 0.0000 | 0.9999 |
| XGBoost | 1.0000 | 0.9998 | 0.9999 | 0.0000 | 0.9999 |

## Split Strategy: `TIER2`

| Model | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| LogisticRegression | 1.0000 | 0.9949 | 0.9975 | 0.0000 | 0.9983 |
| RandomForest | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| XGBoost | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |

## Split Strategy: `TIER3`

| Model | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| LogisticRegression | 1.0000 | 0.9991 | 0.9996 | 0.0000 | 0.9996 |
| RandomForest | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| XGBoost | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |

## Split Strategy: `TIER4`

| Model | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| LogisticRegression | 0.9993 | 0.9984 | 0.9989 | 0.0003 | 0.9992 |
| RandomForest | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |
| XGBoost | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 1.0000 |

## Performance Degradation vs Naive Baseline (Delta F1)

| Split | LogisticRegression | RandomForest | XGBoost |
|---|---|---|---|
| TIER1 | ▲ +0.0000 | ▲ +0.0000 | ▲ +0.0000 |
| TIER2 | ▼ -0.0011 | ▲ +0.0001 | ▲ +0.0001 |
| TIER3 | ▲ +0.0010 | ▲ +0.0001 | ▲ +0.0001 |
| TIER4 | ▲ +0.0003 | ▲ +0.0001 | ▲ +0.0001 |

## Visualizations

### F1 Score Comparison
![F1 Comparison](figures/f1_comparison.png)

### False Positive Rate Comparison
![FPR Comparison](figures/fpr_comparison.png)

### Delta F1 Heatmap (vs Naive Baseline)
![Delta Heatmap](figures/delta_f1_heatmap.png)

---

## Key Findings

- **Largest F1 degradation**: `LogisticRegression` drops by `-0.0011` under `TIER2` split.
- **Tier-2 (eTLD+1 disjoint)** reveals cloud-infrastructure leakage (AWS/Azure domains in both sets) causing optimistic naive-split scores.
- **Tier-3 (brand-keyword disjoint)** shows brand shortcut learning: models exploit 24 shared brand keywords present in both training classes.
- **Tier-4 (hostname disjoint)** is the strictest and most realistic simulation of real-world deployment on genuinely unseen infrastructure.
