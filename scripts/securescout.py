#!/usr/bin/env python3
"""
SecureScout - Professional Cloud Security Platform
Advanced infrastructure security assessment and vulnerability analysis
"""

import sys
import os

def main():
    """SecureScout main entry point"""
    
    # Check if cloud arguments are present
    cloud_keywords = [
        '--cloud-scan', '--cloud-providers', '--cloud-tags', 
        '--cloud-only', '--cloud-risk-analysis', '--export-cloud-targets'
    ]
    
    is_cloud_mode = any(arg in sys.argv for arg in cloud_keywords)
    
    # Navigate to project root (parent directory of scripts)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Route to appropriate engine
    if is_cloud_mode:
        print("🌐 SecureScout Cloud Security Platform")
        os.system(f"python3 {project_root}/core/nmap_automator_cloud_simple.py " + " ".join(sys.argv[1:]))
    else:
        print("🔍 SecureScout Network Security Assessment")  
        os.system(f"python3 {project_root}/core/nmap_automator_optimized.py " + " ".join(sys.argv[1:]))

if __name__ == '__main__':
    main()