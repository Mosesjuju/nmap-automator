#!/usr/bin/env python3
"""
SecureScout Performance Dashboard
Real-time monitoring interface for scan performance, cache analytics, and system metrics
"""

import json
import time
import psutil
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any

class PerformanceDashboard:
    """Real-time performance monitoring and analytics dashboard"""
    
    def __init__(self, cache_manager=None):
        self.cache_manager = cache_manager
        self.metrics = {
            "scan_performance": [],
            "cache_analytics": {},
            "system_metrics": {},
            "security_trends": []
        }
        self._monitoring = False
        self._monitor_thread = None
        
    def start_monitoring(self):
        """Start real-time performance monitoring"""
        self._monitoring = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        print("📊 Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join()
        print("📊 Performance monitoring stopped")
    
    def _monitor_loop(self):
        """Continuous monitoring loop"""
        while self._monitoring:
            self._collect_metrics()
            time.sleep(5)  # Collect metrics every 5 seconds
    
    def _collect_metrics(self):
        """Collect comprehensive performance metrics"""
        timestamp = datetime.now()
        
        # System metrics
        system_metrics = {
            "timestamp": timestamp.isoformat(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "memory_available": psutil.virtual_memory().available / (1024**3),  # GB
            "disk_usage": psutil.disk_usage('/').percent,
            "network_io": psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
            "process_count": len(psutil.pids())
        }
        
        self.metrics["system_metrics"] = system_metrics
        
        # Cache analytics
        if self.cache_manager:
            cache_stats = self.cache_manager.get_analytics()
            self.metrics["cache_analytics"] = {
                "timestamp": timestamp.isoformat(),
                **cache_stats
            }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        cache_stats = self.metrics.get("cache_analytics", {})
        system_stats = self.metrics.get("system_metrics", {})
        
        return {
            "dashboard_status": "Active" if self._monitoring else "Inactive",
            "last_updated": datetime.now().isoformat(),
            "cache_performance": {
                "hit_rate": cache_stats.get("hit_rate", 0),
                "total_entries": cache_stats.get("entries", 0),
                "memory_usage": cache_stats.get("memory_usage_mb", 0),
                "performance_gain": cache_stats.get("performance_improvement", "N/A")
            },
            "system_health": {
                "cpu_usage": system_stats.get("cpu_percent", 0),
                "memory_usage": system_stats.get("memory_percent", 0),
                "disk_usage": system_stats.get("disk_usage", 0),
                "status": self._get_health_status(system_stats)
            },
            "scan_metrics": {
                "total_scans": len(self.metrics["scan_performance"]),
                "average_duration": self._calculate_avg_scan_time(),
                "success_rate": self._calculate_success_rate()
            }
        }
    
    def _get_health_status(self, system_stats: Dict) -> str:
        """Determine system health status"""
        cpu = system_stats.get("cpu_percent", 0)
        memory = system_stats.get("memory_percent", 0)
        
        if cpu > 90 or memory > 90:
            return "Critical"
        elif cpu > 70 or memory > 70:
            return "Warning" 
        else:
            return "Healthy"
    
    def _calculate_avg_scan_time(self) -> float:
        """Calculate average scan duration"""
        if not self.metrics["scan_performance"]:
            return 0.0
        
        durations = [scan.get("duration", 0) for scan in self.metrics["scan_performance"]]
        return sum(durations) / len(durations) if durations else 0.0
    
    def _calculate_success_rate(self) -> float:
        """Calculate scan success rate percentage"""
        if not self.metrics["scan_performance"]:
            return 100.0
        
        successful = sum(1 for scan in self.metrics["scan_performance"] if scan.get("status") == "success")
        return (successful / len(self.metrics["scan_performance"])) * 100
    
    def record_scan_performance(self, scan_data: Dict[str, Any]):
        """Record scan performance metrics"""
        performance_record = {
            "timestamp": datetime.now().isoformat(),
            "target": scan_data.get("target", "unknown"),
            "scan_type": scan_data.get("scan_type", "unknown"), 
            "duration": scan_data.get("duration", 0),
            "status": scan_data.get("status", "unknown"),
            "cache_hit": scan_data.get("cache_hit", False),
            "vulnerabilities_found": len(scan_data.get("vulnerabilities", [])),
            "risk_score": scan_data.get("risk_score", 0)
        }
        
        self.metrics["scan_performance"].append(performance_record)
        
        # Keep only last 100 scan records
        if len(self.metrics["scan_performance"]) > 100:
            self.metrics["scan_performance"] = self.metrics["scan_performance"][-100:]
    
    def generate_performance_report(self) -> str:
        """Generate comprehensive performance report"""
        summary = self.get_performance_summary()
        
        report = f"""
🚀 SECURESCOUT PERFORMANCE DASHBOARD
===================================
Report Generated: {summary['last_updated']}
Dashboard Status: {summary['dashboard_status']}

🧠 CACHE PERFORMANCE
===================
Hit Rate: {summary['cache_performance']['hit_rate']:.2f}%
Total Entries: {summary['cache_performance']['total_entries']}
Memory Usage: {summary['cache_performance']['memory_usage']:.2f} MB
Performance Gain: {summary['cache_performance']['performance_gain']}

🖥️  SYSTEM HEALTH
================
CPU Usage: {summary['system_health']['cpu_usage']:.1f}%
Memory Usage: {summary['system_health']['memory_usage']:.1f}%  
Disk Usage: {summary['system_health']['disk_usage']:.1f}%
Status: {summary['system_health']['status']}

📊 SCAN METRICS
==============
Total Scans: {summary['scan_metrics']['total_scans']}
Average Duration: {summary['scan_metrics']['average_duration']:.2f}s
Success Rate: {summary['scan_metrics']['success_rate']:.1f}%

🔍 RECENT SCAN ACTIVITY
======================
"""
        
        # Add recent scans
        recent_scans = self.metrics["scan_performance"][-5:] if self.metrics["scan_performance"] else []
        for scan in recent_scans:
            cache_indicator = "🧠" if scan["cache_hit"] else "🔄"
            report += f"{cache_indicator} {scan['target']} - {scan['duration']:.2f}s - {scan['vulnerabilities_found']} vulns\n"
        
        if not recent_scans:
            report += "No recent scan activity\n"
        
        return report
    
    def export_metrics(self, format_type: str = "json") -> str:
        """Export performance metrics in specified format"""
        if format_type == "json":
            return json.dumps({
                "exported_at": datetime.now().isoformat(),
                "summary": self.get_performance_summary(),
                "detailed_metrics": self.metrics
            }, indent=2)
        
        elif format_type == "csv":
            # Simple CSV export for scan performance
            csv_data = "timestamp,target,scan_type,duration,status,cache_hit,vulnerabilities,risk_score\n"
            for scan in self.metrics["scan_performance"]:
                csv_data += f"{scan['timestamp']},{scan['target']},{scan['scan_type']},"
                csv_data += f"{scan['duration']},{scan['status']},{scan['cache_hit']},"
                csv_data += f"{scan['vulnerabilities_found']},{scan['risk_score']}\n"
            return csv_data
        
        else:
            return self.generate_performance_report()

def main():
    """Demo function for performance dashboard"""
    print("📊 SecureScout Performance Dashboard v2.0")
    print("=" * 50)
    
    dashboard = PerformanceDashboard()
    
    # Start monitoring
    dashboard.start_monitoring()
    
    # Simulate some scan data
    print("📡 Simulating scan activity...")
    for i in range(5):
        scan_data = {
            "target": f"target{i+1}.com",
            "scan_type": "comprehensive",
            "duration": 10.5 + i,
            "status": "success",
            "cache_hit": i % 2 == 0,
            "vulnerabilities": ["XSS", "SQL Injection"][:i],
            "risk_score": 30 + i * 10
        }
        dashboard.record_scan_performance(scan_data)
        time.sleep(1)
    
    # Generate report
    print("\n" + dashboard.generate_performance_report())
    
    # Export metrics
    metrics_file = f"performance_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(f"results/{metrics_file}", 'w') as f:
        f.write(dashboard.export_metrics("json"))
    
    print(f"\n📄 Metrics exported to: results/{metrics_file}")
    
    # Stop monitoring
    dashboard.stop_monitoring()

if __name__ == "__main__":
    main()