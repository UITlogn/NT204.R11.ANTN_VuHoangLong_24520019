import glob
import os
import subprocess
import sys

COMBINED_FILE = "TEST/all_bt2_results.jsonl"

print("--- Running Decoder Tests (T01 - T04) ---")
subprocess.run([sys.executable, "test_decoder.py"], check=True)

print("--- Running Preprocessor Tests (T05, T06, T14) ---")
subprocess.run([sys.executable, "test_preprocessor.py"], check=True)

print("--- Running Flow Tracker Tests (T07 - T13) ---")
subprocess.run([sys.executable, "test_flow_tracker.py"], check=True)

# Gộp kết quả
if os.path.exists(COMBINED_FILE):
    os.remove(COMBINED_FILE)

res_files = sorted(glob.glob("TEST/res_t*.jsonl"))
with open(COMBINED_FILE, "w", encoding="utf-8") as outfile:
    for rf in res_files:
        with open(rf, "r", encoding="utf-8") as infile:
            outfile.write(infile.read().strip() + "\n")

print(f"Aggregated {len(res_files)} test results into {COMBINED_FILE}")