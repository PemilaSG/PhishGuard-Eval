"""
splitter.py
===========
Step 3 — Automated Domain-Disjoint Split Generator (RQ4)

Produces 5 split strategies from dataset.csv:
  naive       — standard random 80/20 split (baseline)
  tier1       — deduplicated URLs, then random split
  tier2       — eTLD+1 domain-disjoint split
  tier3       — brand-keyword disjoint split
  tier4       — hostname/IP-disjoint split (strictest)

Each split is saved to:
  data/splits/<strategy>_train.csv
  data/splits/<strategy>_test.csv
"""

import os, sys, io, json
import pandas as pd
import numpy as np
from collections import defaultdict

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROC      = os.path.join(ROOT, "data", "processed")
SPLIT_DIR = os.path.join(ROOT, "data", "splits")
os.makedirs(SPLIT_DIR, exist_ok=True)

DATASET_PATH = os.path.join(PROC, "dataset.csv")
SEED = 42

FEATURE_COLS = [
    "is_ip","url_length","hostname_length","path_length","num_dots",
    "num_hyphens","num_underscores","num_digits","num_subdomains",
    "has_https","has_at_symbol","has_double_slash","has_hex_encoding",
    "tld_length","path_depth","url_entropy","has_brand_keyword",
    "query_length","num_special_chars"
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def save_split(train: pd.DataFrame, test: pd.DataFrame, name: str):
    train.to_csv(os.path.join(SPLIT_DIR, f"{name}_train.csv"), index=False)
    test.to_csv(os.path.join(SPLIT_DIR,  f"{name}_test.csv"),  index=False)
    print(f"  [{name:8s}] train={len(train):,}  test={len(test):,}  "
          f"(phish_test={test['label'].sum():,}  legit_test={(test['label']==0).sum():,})")

def group_disjoint_split(df: pd.DataFrame, group_col: str,
                          test_frac=0.20, seed=SEED) -> tuple:
    """
    Splits by group (no group appears in both train and test).
    Attempts to keep test_frac of total rows in test while balancing classes.
    """
    rng = np.random.default_rng(seed)
    groups = df[group_col].unique()
    rng.shuffle(groups)

    # Assign groups greedily until we have ~test_frac of rows
    target_test = int(len(df) * test_frac)
    test_groups, train_groups = [], []
    test_size = 0
    for g in groups:
        g_size = (df[group_col] == g).sum()
        if test_size < target_test:
            test_groups.append(g)
            test_size += g_size
        else:
            train_groups.append(g)

    train = df[df[group_col].isin(train_groups)].copy()
    test  = df[df[group_col].isin(test_groups)].copy()
    return train, test

# ── Split strategies ──────────────────────────────────────────────────────────

def split_naive(df: pd.DataFrame):
    test  = df.sample(frac=0.20, random_state=SEED)
    train = df.drop(test.index)
    save_split(train, test, "naive")

def split_tier1(df: pd.DataFrame):
    """Tier-1: deduplicate canonical URLs first, then random split."""
    df_deduped = df.drop_duplicates(subset=["url"])
    test  = df_deduped.sample(frac=0.20, random_state=SEED)
    train = df_deduped.drop(test.index)
    save_split(train, test, "tier1")

def split_tier2(df: pd.DataFrame):
    """Tier-2: eTLD+1 domain-disjoint split."""
    train, test = group_disjoint_split(df, "etld_plus_one")
    save_split(train, test, "tier2")

def split_tier3(df: pd.DataFrame):
    """Tier-3: brand-keyword group-disjoint split.
       URLs with no brand keyword are randomly distributed.
       URLs sharing the same brand keyword stay in the same partition.
    """
    branded    = df[df["brand_keyword"] != ""].copy()
    unbranded  = df[df["brand_keyword"] == ""].copy()

    tr_b, te_b   = group_disjoint_split(branded,   "brand_keyword")
    te_ub  = unbranded.sample(frac=0.20, random_state=SEED)
    tr_ub  = unbranded.drop(te_ub.index)

    train = pd.concat([tr_b, tr_ub], ignore_index=True)
    test  = pd.concat([te_b, te_ub], ignore_index=True)
    save_split(train, test, "tier3")

def split_tier4(df: pd.DataFrame):
    """Tier-4: hostname/IP disjoint split — strictest level."""
    train, test = group_disjoint_split(df, "hostname")
    save_split(train, test, "tier4")

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=== Step 3: Automated Domain-Disjoint Split Generator ===\n")
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    df["brand_keyword"] = df["brand_keyword"].fillna("")
    df["etld_plus_one"] = df["etld_plus_one"].fillna(df["hostname"])
    df["hostname"]      = df["hostname"].fillna("unknown")
    print(f"Dataset loaded: {len(df):,} rows  |  "
          f"Phishing={df['label'].sum():,}  Legit={(df['label']==0).sum():,}\n")
    print("Generating splits:")
    split_naive(df)
    split_tier1(df)
    split_tier2(df)
    split_tier3(df)
    split_tier4(df)

    # Save feature column list for model scripts
    meta = {"feature_cols": FEATURE_COLS, "label_col": "label"}
    with open(os.path.join(PROC, "feature_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n[OK] All splits saved to data/splits/")
    print(f"[OK] Feature metadata saved to data/processed/feature_meta.json")

if __name__ == "__main__":
    main()
