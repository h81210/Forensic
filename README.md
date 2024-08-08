Forensic Tool
A Python-based forensic tool designed for cybersecurity professionals to extract and analyze crucial information from various data sources. This tool can:

Extract IP addresses and URLs from a PCAP file.
Calculate file hashes for integrity verification.
Retrieve metadata information using ExifTool.
Monitor network traffic.
Extract all files from a forensic image.
Search for strings within files.
Analyze log files by defining keywords.
Perform brute-force attacks using a wordlist.
Dependencies:
hashlib
os
re
scapy
pytshark
pyewf
How to Run:
Clone the repository and run the tool using Python 3.

bash
Copy code
git clone <repository-url>
cd ForensicTool
python3 forensic_tool.py
