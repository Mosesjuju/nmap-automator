#!/usr/bin/env python3
"""
SecureScout Unified Launcher v1.3.0
Intelligent routing between traditional network scanning and cloud security assessment
"""

import sys
import os

def main():
    """Intelligent launcher for SecureScout"""
    
    # Check if cloud arguments are present
    cloud_keywords = [
        '--cloud-scan', '--cloud-providers', '--cloud-tags', 
        '--cloud-only', '--cloud-risk-analysis', '--export-cloud-targets'
    ]
    
    is_cloud_mode = any(arg in sys.argv for arg in cloud_keywords)
    
    # Route to appropriate version
    if is_cloud_mode:
        print("🌐 Launching SecureScout Cloud Security Platform v1.3.0...")
        os.system(f"python3 {os.path.dirname(__file__)}/nmap_automator_cloud_simple.py " + " ".join(sys.argv[1:]))
    else:
        print("🔍 Launching SecureScout Traditional Scanning v1.2.1...")  
        os.system(f"python3 {os.path.dirname(__file__)}/nmap_automator_optimized.py " + " ".join(sys.argv[1:]))

if __name__ == '__main__':
    main()
