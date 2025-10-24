#!/usr/bin/env python3
"""
Test script for the new Performance Logger system
Demonstrates the detailed performance tracking capabilities
"""

import sys
import os
import time

# Add tools directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

from performance_logger import performance_logger, PerformanceContext, track_performance
from banner_generator import display_banner

def simulate_nmap_scan(target, scan_type="fast"):
    """Simulate an nmap scan with performance tracking"""
    
    # Start performance tracking for the scan
    with PerformanceContext("nmap", target, {"scan_type": scan_type}):
        print(f"🔍 Scanning {target} with {scan_type} scan...")
        
        # Simulate scan time based on type
        if scan_type == "fast":
            time.sleep(2)
        elif scan_type == "comprehensive":
            time.sleep(4)
        else:
            time.sleep(3)
        
        # Log some events during the scan
        performance_logger.log_event("port_discovered", "nmap", target, 
                                   {"port": 22, "service": "ssh", "state": "open"})
        
        performance_logger.log_event("port_discovered", "nmap", target, 
                                   {"port": 80, "service": "http", "state": "open"})
        
        if scan_type == "comprehensive":
            # Simulate vulnerability discovery
            performance_logger.log_event("vulnerability_found", "nmap", target, 
                                       {"cve": "CVE-2023-1234", "severity": "medium"})
        
        print(f"✅ Scan of {target} completed")

def simulate_nikto_scan(target):
    """Simulate a nikto scan with performance tracking"""
    
    with PerformanceContext("nikto", target, {"scan_type": "web_vuln"}):
        print(f"🌐 Running Nikto scan on {target}...")
        time.sleep(3)
        
        # Log nikto findings
        performance_logger.log_event("vulnerability_found", "nikto", target, 
                                   {"type": "outdated_software", "severity": "low"})
        
        performance_logger.log_event("vulnerability_found", "nikto", target, 
                                   {"type": "directory_traversal", "severity": "high"})
        
        print(f"✅ Nikto scan of {target} completed")

@track_performance("gobuster", "example.com")
def simulate_gobuster_scan():
    """Simulate gobuster scan using decorator"""
    print("📁 Running Gobuster directory scan...")
    time.sleep(1.5)
    
    performance_logger.log_event("directory_found", "gobuster", "example.com", 
                               {"path": "/admin", "status": 200})
    
    performance_logger.log_event("directory_found", "gobuster", "example.com", 
                               {"path": "/backup", "status": 403})
    
    print("✅ Gobuster scan completed")

def main():
    """Main test function"""
    
    # Display banner
    print("\n" + "="*60)
    display_banner("performance_logger", "96")  # Bright cyan
    print("PERFORMANCE LOGGER TEST SUITE")
    print("="*60)
    
    # Test multiple operations
    targets = ["example.com", "testsite.org", "demo.local"]
    
    # Run various scans
    for target in targets:
        simulate_nmap_scan(target, "fast")
        time.sleep(0.5)
    
    # Run comprehensive scan
    simulate_nmap_scan("example.com", "comprehensive")
    
    # Run other tools
    simulate_nikto_scan("example.com")
    simulate_gobuster_scan()
    
    # Show performance summary
    print(f"\n📊 PERFORMANCE SUMMARY")
    print("="*40)
    
    summary = performance_logger.get_performance_summary(1)  # Last hour
    
    if summary.get('completed_operations', 0) > 0:
        print(f"✅ Operations completed: {summary['completed_operations']}")
        print(f"📈 Success rate: {summary['success_rate']}%")
        print(f"⏱️  Average duration: {summary['performance_metrics']['avg_duration_seconds']:.2f}s")
        print(f"🧠 Average memory delta: {summary['performance_metrics']['avg_memory_delta_mb']:.2f}MB")
        
        print(f"\n📋 BY OPERATION TYPE:")
        for op_type, stats in summary.get('by_operation', {}).items():
            print(f"   {op_type.upper()}: {stats['count']} operations, avg {stats['avg_duration']:.2f}s")
    else:
        print("No operations completed in the last hour")
    
    # Generate reports in different formats
    print(f"\n💾 GENERATING REPORTS...")
    
    json_report = performance_logger.save_performance_report("json", 1)
    print(f"📄 JSON report: {json_report}")
    
    csv_report = performance_logger.save_performance_report("csv", 1)
    print(f"📊 CSV report: {csv_report}")
    
    txt_report = performance_logger.save_performance_report("txt", 1)
    print(f"📝 Text report: {txt_report}")
    
    print(f"\n🎉 Performance logging test completed!")
    print(f"Check the results/performance_logs/ directory for detailed reports.")

if __name__ == "__main__":
    main()