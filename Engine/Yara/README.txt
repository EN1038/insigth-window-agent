SOSECURE YARA ENGINE SETUP
==========================

yara64.exe is NOT shipped in this repository (license / binary size).

To enable threat scanning, place the following files in this directory:

1. yara64.exe  - The official YARA 64-bit command line tool
               (from https://github.com/VirusTotal/yara/releases)
2. rules.yar   - Optional local rules; production rules sync from Center

The agent runs YARA against scanned files after a successful administrator
login. Scanning runs in the background at low priority.
