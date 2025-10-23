#!/usr/bin/env python3
# Cloud Platform Validation Script

import sys
import importlib
from pathlib import Path

def validate_cloud_platform():
    print("🔍 Validating Cloud Platform Installation...")
    print("=" * 50)
    
    # Check required files
    required_files = [
        "nmap_automator_cloud.py",
        "cloud_scanning.py", 
        "cloud_config.json",
        "requirements-cloud.txt"
    ]
    
    missing_files = []
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
        else:
            print(f"✅ {file}")
    
    if missing_files:
        print(f"❌ Missing files: {', '.join(missing_files)}")
        return False
    
    # Check Python dependencies
    print("\n🐍 Checking Python Dependencies...")
    required_modules = [
        "boto3", "azure.mgmt.compute", "google.cloud.compute",
        "aiohttp", "pydantic", "rich"
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            importlib.import_module(module)
            print(f"✅ {module}")
        except ImportError:
            missing_modules.append(module)
            print(f"❌ {module}")
    
    if missing_modules:
        print(f"\n⚠️ Install missing modules: pip install -r requirements-cloud.txt")
    
    # Overall status
    print("\n" + "=" * 50)
    if not missing_files and not missing_modules:
        print("🎉 Cloud Platform is ready for use!")
        return True
    else:
        print("⚠️ Cloud Platform setup incomplete")
        return False

if __name__ == "__main__":
    success = validate_cloud_platform()
    sys.exit(0 if success else 1)
