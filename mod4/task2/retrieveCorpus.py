#!/usr/bin/env python3
import os
import shutil
from pathlib import Path

# --- Make HTTPS work inside the venv (uses certifi from requirements.txt) ---
try:
    import certifi  #For some reason, I didn't have a valid cert without this to retrieve from nltk
    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
except Exception:
    pass

import nltk

# create a temporary dir in script dir to download nltk_data.
LOCAL_NLTK_DIR = Path.cwd() / "nltk_data"
os.makedirs(LOCAL_NLTK_DIR, exist_ok=True)
if str(LOCAL_NLTK_DIR) not in nltk.data.path:
    nltk.data.path.insert(0, str(LOCAL_NLTK_DIR))

# --- Ensure corpus is present (download to LOCAL_NLTK_DIR if missing) ---
from nltk.corpus import words
try:
    word_list = words.words()
except LookupError:
    nltk.download("words", download_dir=str(LOCAL_NLTK_DIR), quiet=True, raise_on_error=True)
    word_list = words.words()

# --- Filter words 6–10 letters long (inclusive) ---
filtered_words = [w for w in word_list if 6 <= len(w) <= 10]

# Write 6-10 letter words to file in script dir.
output_file = Path.cwd() / "nltk_corpus.txt"
with open(output_file, "w", encoding="utf-8") as f:
    f.write("\n".join(filtered_words))

print(f"Saved {len(filtered_words)} words (6–10 letters) to {output_file}")

# Remove nltk_corpus data directy
if LOCAL_NLTK_DIR.exists():
    shutil.rmtree(LOCAL_NLTK_DIR)
    print(f"Deleted local NLTK data directory: {LOCAL_NLTK_DIR}")
else:
    print("No local NLTK data directory found to delete.")
