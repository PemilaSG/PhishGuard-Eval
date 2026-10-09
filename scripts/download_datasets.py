import os
import urllib.request
import zipfile
import json
import csv

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "raw")
os.makedirs(DATA_DIR, exist_ok=True)

def download_file(url, destination):
    print(f"Downloading {url} -> {destination}...")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as response, open(destination, 'wb') as out_file:
        out_file.write(response.read())
    print(f"Successfully downloaded to {destination}")

def download_tranco():
    """Download latest Tranco Top 1M legitimate domains list."""
    tranco_zip = os.path.join(DATA_DIR, "tranco_top1m.zip")
    tranco_csv = os.path.join(DATA_DIR, "tranco_top1m.csv")
    
    # Tranco list download endpoint
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        download_file(url, tranco_zip)
        print("Extracting Tranco ZIP...")
        with zipfile.ZipFile(tranco_zip, 'r') as zip_ref:
            zip_ref.extractall(DATA_DIR)
            # Find extracted file and ensure standard name
            for name in zip_ref.namelist():
                extracted_path = os.path.join(DATA_DIR, name)
                if extracted_path != tranco_csv and os.path.exists(extracted_path):
                    if os.path.exists(tranco_csv):
                        os.remove(tranco_csv)
                    os.rename(extracted_path, tranco_csv)
        print("Tranco Top 1M successfully acquired.")
    except Exception as e:
        print(f"Failed to download Tranco: {e}")

def download_urlhaus():
    """Download latest URLhaus active phishing URLs feed (CSV)."""
    urlhaus_csv = os.path.join(DATA_DIR, "urlhaus_full.csv")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        download_file(url, urlhaus_csv)
        print("URLhaus recent dataset successfully acquired.")
    except Exception as e:
        print(f"Failed to download URLhaus: {e}")

def download_openphish():
    """Download OpenPhish community feed."""
    openphish_txt = os.path.join(DATA_DIR, "openphish_feed.txt")
    url = "https://openphish.com/feed.txt"
    try:
        download_file(url, openphish_txt)
        print("OpenPhish community feed successfully acquired.")
    except Exception as e:
        print(f"Failed to download OpenPhish: {e}")

if __name__ == "__main__":
    print("Starting Step 1: Dataset Acquisition...")
    download_tranco()
    download_urlhaus()
    download_openphish()
    print("\nDataset acquisition completed!")
