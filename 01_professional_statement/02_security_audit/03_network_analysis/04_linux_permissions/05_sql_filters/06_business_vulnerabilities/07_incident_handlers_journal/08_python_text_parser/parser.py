"""Simple log parser for security-related events.

Usage:
    python parser.py input_log.txt output_alerts.txt

The script reads a plain-text log file line by line and writes only the
lines that contain suspicious keywords (e.g., FAILED LOGIN, ERROR, WARNING)
to the output file. This demonstrates how Python can help automate
basic security log analysis tasks.
"""

import sys

SUSPICIOUS_KEYWORDS = [
    "FAILED LOGIN",
    "Failed password",
    "ERROR",
    "WARNING",
    "unauthorized",
    "denied"
]

def parse_log(input_file, output_file):
    """Read input_file and write lines containing any suspicious keywords
    to output_file.
    """
    with open(input_file, "r", encoding="utf-8") as infile, open(output_file, "w", encoding="utf-8") as outfile:
        for line in infile:
            if any(keyword in line for keyword in SUSPICIOUS_KEYWORDS):
                outfile.write(line)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python parser.py input_log.txt output_alerts.txt")
        sys.exit(1)
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    parse_log(input_path, output_path)
    print(f"Filtered alerts written to {output_path}")
