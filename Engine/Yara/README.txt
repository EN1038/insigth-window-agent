SOSECURE YARA ENGINE SETUP
==========================

To enable threat scanning, please place the following files in this directory:

1. yara64.exe  - The official YARA 64-bit command line tool.
2. rules.yar   - Your YARA rules file.

The agent will automatically execute these rules against all system files after a successful administrator login.
Scanning runs in the background at low priority.
