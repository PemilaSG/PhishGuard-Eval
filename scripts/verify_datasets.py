import os
import csv

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "raw")

def verify():
    print("=== Dataset Acquisition Verification Report ===")
    
    # 1. Tranco
    tranco_path = os.path.join(DATA_DIR, "tranco_top1m.csv")
    if os.path.exists(tranco_path):
        with open(tranco_path, "r", encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for _ in f)
        print(f"[Legitimate] Tranco Top 1M: {line_count:,} domains | Path: {tranco_path}")
        
    # 2. URLhaus
    urlhaus_path = os.path.join(DATA_DIR, "urlhaus_full.csv")
    if os.path.exists(urlhaus_path):
        with open(urlhaus_path, "r", encoding="utf-8", errors="ignore") as f:
            # Skip comment lines starting with #
            urls = [line for line in f if not line.startswith("#")]
        print(f"[Phishing] URLhaus Recent Feed: {len(urls):,} records | Path: {urlhaus_path}")
        
    # 3. OpenPhish
    openphish_path = os.path.join(DATA_DIR, "openphish_feed.txt")
    if os.path.exists(openphish_path):
        with open(openphish_path, "r", encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"[Phishing] OpenPhish Live Feed: {len(urls):,} URLs | Path: {openphish_path}")

if __name__ == "__main__":
    verify()
