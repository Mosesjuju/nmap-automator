#!/usr/bin/env python3
from colorama import init
init(autoreset=True)

from nmap_automator_new import print_banner, print_nikto_banner, progress_bar

print("\n=== NMAP Banner ===\n")
print_banner()

print("\n=== Nikto Banner ===\n")
print_nikto_banner()

print("\n=== Dashed Progress Bar Demo ===\n")
progress_bar(20)
print("\n[OK] ASCII test completed.\n")
