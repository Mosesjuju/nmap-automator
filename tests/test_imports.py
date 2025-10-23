#!/usr/bin/env python3
"""Test imports to debug the 12 problems"""

import sys
import os

# Add tools directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

print("Testing imports...")

# Test external packages
try:
    import schedule
    print("✅ schedule imported successfully")
except ImportError as e:
    print(f"❌ schedule import failed: {e}")

try:
    from tqdm import tqdm
    print("✅ tqdm imported successfully")
except ImportError as e:
    print(f"❌ tqdm import failed: {e}")

try:
    from colorama import Fore, Style, init
    print("✅ colorama imported successfully")
except ImportError as e:
    print(f"❌ colorama import failed: {e}")

try:
    import aiofiles
    print("✅ aiofiles imported successfully")
except ImportError as e:
    print(f"❌ aiofiles import failed: {e}")

try:
    import psutil
    print("✅ psutil imported successfully")
except ImportError as e:
    print(f"❌ psutil import failed: {e}")

# Test local modules
try:
    from vuln_analyzer import VulnerabilityAnalyzer
    print("✅ vuln_analyzer imported successfully")
except ImportError as e:
    print(f"❌ vuln_analyzer import failed: {e}")

try:
    from tool_chain import ToolChain, show_available_tools, print_tool_chain_banner
    print("✅ tool_chain imported successfully")
except ImportError as e:
    print(f"❌ tool_chain import failed: {e}")

try:
    from burp_integration import create_burp_integration, print_burp_banner, check_burp_availability
    print("✅ burp_integration imported successfully")
except ImportError as e:
    print(f"❌ burp_integration import failed: {e}")

try:
    from performance_optimizer import (
        performance_optimized, 
        PerformanceProfiler,
        OptimizedExecutor,
        global_cache,
        get_optimal_thread_count,
        cleanup_performance_resources
    )
    print("✅ performance_optimizer imported successfully")
except ImportError as e:
    print(f"❌ performance_optimizer import failed: {e}")

try:
    from async_scan_engine import AsyncScanEngine, async_quick_scan, async_nmap_scan
    print("✅ async_scan_engine imported successfully")
except ImportError as e:
    print(f"❌ async_scan_engine import failed: {e}")

try:
    from evasion_profiles import (
        EvasionProfileManager,
        TrafficAnalysisCounter
    )
    print("✅ evasion_profiles imported successfully")
except ImportError as e:
    print(f"❌ evasion_profiles import failed: {e}")

print("\nImport testing completed!")