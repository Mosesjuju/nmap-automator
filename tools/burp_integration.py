#!/usr/bin/env python3
"""
Burp Suite REST API Integration for NMAP Automator v1.1.1
Provides automated web application security scanning using Burp Suite Professional
"""

import requests
import json
import time
import logging
import os
import base64
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import threading
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


class BurpScanStatus(Enum):
    """Burp scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class BurpScanConfig:
    """Burp scan configuration"""
    target_url: str
    scan_type: str = "active"  # active, passive, crawl_only
    crawl_strategy: str = "most_complete"  # fast, thorough, most_complete
    audit_items: List[str] = None
    max_crawl_time: int = 300  # 5 minutes default
    max_audit_time: int = 900  # 15 minutes default
    scope_advanced_mode: bool = False
    application_login: Dict = None


@dataclass 
class BurpScanResult:
    """Burp scan result container"""
    task_id: str
    status: BurpScanStatus
    target_url: str
    start_time: float
    end_time: Optional[float]
    issues_count: int
    scan_metrics: Dict
    issues: List[Dict]
    report_path: Optional[str] = None


class BurpSuiteAPI:
    """Burp Suite REST API client"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 1337, api_key: str = None):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.base_url = f"http://{host}:{port}"
        self.session = requests.Session()
        
        # Set API key header if provided
        if api_key:
            self.session.headers.update({"X-API-Key": api_key})
            
        # Disable SSL warnings for self-signed certs
        requests.packages.urllib3.disable_warnings()
        
    def check_connection(self) -> bool:
        """Test connection to Burp Suite API"""
        try:
            response = self.session.get(f"{self.base_url}/burp/versions")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Failed to connect to Burp Suite API: {e}")
            return False
            
    def get_burp_version(self) -> Dict:
        """Get Burp Suite version information"""
        try:
            response = self.session.get(f"{self.base_url}/burp/versions")
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception as e:
            logger.error(f"Error getting Burp version: {e}")
            return {}
            
    def start_scan(self, config: BurpScanConfig) -> Optional[str]:
        """Start a new Burp scan and return task ID"""
        try:
            # Prepare scan configuration
            scan_data = {
                "scan_configurations": [
                    {
                        "name": f"automated_scan_{int(time.time())}",
                        "type": config.scan_type
                    }
                ],
                "application_logins": [],
                "urls": [config.target_url]
            }
            
            # Add crawl configuration
            if config.scan_type in ["active", "crawl_only"]:
                scan_data["crawl_configuration"] = {
                    "strategy": config.crawl_strategy,
                    "max_crawl_time": config.max_crawl_time
                }
                
            # Add audit configuration for active scans
            if config.scan_type == "active":
                scan_data["audit_configuration"] = {
                    "max_audit_time": config.max_audit_time
                }
                
                if config.audit_items:
                    scan_data["audit_configuration"]["audit_items"] = config.audit_items
                    
            # Add application login if provided
            if config.application_login:
                scan_data["application_logins"].append(config.application_login)
                
            logger.info(f"Starting Burp scan for {config.target_url}")
            response = self.session.post(
                f"{self.base_url}/burp/scanner/scans/active",
                json=scan_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 201:
                result = response.json()
                task_id = result.get("task_id")
                logger.info(f"Burp scan started successfully: Task ID {task_id}")
                return task_id
            else:
                logger.error(f"Failed to start Burp scan: HTTP {response.status_code}")
                logger.error(f"Response: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Error starting Burp scan: {e}")
            return None
            
    def get_scan_status(self, task_id: str) -> Dict:
        """Get scan status and metrics"""
        try:
            response = self.session.get(f"{self.base_url}/burp/scanner/scans/{task_id}")
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception as e:
            logger.error(f"Error getting scan status: {e}")
            return {}
            
    def get_scan_issues(self, task_id: str) -> List[Dict]:
        """Get discovered issues from scan"""
        try:
            response = self.session.get(f"{self.base_url}/burp/scanner/scans/{task_id}/issues")
            if response.status_code == 200:
                return response.json().get("issues", [])
            return []
        except Exception as e:
            logger.error(f"Error getting scan issues: {e}")
            return []
            
    def cancel_scan(self, task_id: str) -> bool:
        """Cancel a running scan"""
        try:
            response = self.session.delete(f"{self.base_url}/burp/scanner/scans/{task_id}")
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error cancelling scan: {e}")
            return False
            
    def generate_report(self, task_id: str, report_format: str = "HTML") -> Optional[str]:
        """Generate and download scan report"""
        try:
            report_data = {
                "issue_types": ["all"],
                "report_format": report_format,  # HTML, XML, JSON
                "include_false_positives": False
            }
            
            response = self.session.post(
                f"{self.base_url}/burp/scanner/scans/{task_id}/report",
                json=report_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                # Save report to file
                timestamp = int(time.time())
                filename = f"burp_report_{task_id}_{timestamp}.{report_format.lower()}"
                filepath = os.path.join("burp_results", filename)
                
                os.makedirs("burp_results", exist_ok=True)
                
                with open(filepath, 'w', encoding='utf-8') as f:
                    if report_format.upper() in ["HTML", "XML"]:
                        f.write(response.text)
                    else:
                        f.write(json.dumps(response.json(), indent=2))
                        
                logger.info(f"Burp report saved to: {filepath}")
                return filepath
                
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None


class BurpScanManager:
    """High-level Burp scan management"""
    
    def __init__(self, api: BurpSuiteAPI):
        self.api = api
        self.active_scans: Dict[str, BurpScanResult] = {}
        self.completed_scans: List[BurpScanResult] = []
        
    def execute_automated_scan(self, target_url: str, scan_config: Dict = None) -> BurpScanResult:
        """Execute a complete automated scan with monitoring"""
        
        # Create scan configuration
        config = BurpScanConfig(
            target_url=target_url,
            scan_type=scan_config.get("scan_type", "active"),
            crawl_strategy=scan_config.get("crawl_strategy", "most_complete"), 
            max_crawl_time=scan_config.get("max_crawl_time", 300),
            max_audit_time=scan_config.get("max_audit_time", 900),
            audit_items=scan_config.get("audit_items", None)
        )
        
        # Start scan
        start_time = time.time()
        task_id = self.api.start_scan(config)
        
        if not task_id:
            return BurpScanResult(
                task_id="failed",
                status=BurpScanStatus.FAILED,
                target_url=target_url,
                start_time=start_time,
                end_time=time.time(),
                issues_count=0,
                scan_metrics={},
                issues=[]
            )
            
        # Create result object
        result = BurpScanResult(
            task_id=task_id,
            status=BurpScanStatus.RUNNING,
            target_url=target_url,
            start_time=start_time,
            end_time=None,
            issues_count=0,
            scan_metrics={},
            issues=[]
        )
        
        self.active_scans[task_id] = result
        
        # Monitor scan progress
        self._monitor_scan(result)
        
        return result
        
    def _monitor_scan(self, result: BurpScanResult) -> None:
        """Monitor scan progress in background thread"""
        def monitor():
            while result.status == BurpScanStatus.RUNNING:
                try:
                    status_data = self.api.get_scan_status(result.task_id)
                    
                    if not status_data:
                        result.status = BurpScanStatus.FAILED
                        break
                        
                    scan_status = status_data.get("scan_status", "unknown")
                    result.scan_metrics = status_data.get("scan_metrics", {})
                    
                    if scan_status in ["succeeded", "finished"]:
                        result.status = BurpScanStatus.COMPLETED
                        result.end_time = time.time()
                        
                        # Get final issues
                        result.issues = self.api.get_scan_issues(result.task_id)
                        result.issues_count = len(result.issues)
                        
                        # Generate report
                        result.report_path = self.api.generate_report(result.task_id, "HTML")
                        
                        # Move to completed
                        self.completed_scans.append(result)
                        if result.task_id in self.active_scans:
                            del self.active_scans[result.task_id]
                            
                        logger.info(f"Burp scan completed: {result.issues_count} issues found")
                        break
                        
                    elif scan_status in ["failed", "cancelled"]:
                        result.status = BurpScanStatus.FAILED
                        result.end_time = time.time()
                        break
                        
                    # Progress update
                    crawl_requests = result.scan_metrics.get("crawl_requests_queued", 0)
                    audit_requests = result.scan_metrics.get("audit_requests_queued", 0)
                    
                    if crawl_requests > 0 or audit_requests > 0:
                        logger.info(f"Burp scan progress: {crawl_requests} crawl, {audit_requests} audit requests")
                        
                    time.sleep(10)  # Check every 10 seconds
                    
                except Exception as e:
                    logger.error(f"Error monitoring Burp scan: {e}")
                    result.status = BurpScanStatus.FAILED
                    break
                    
        # Start monitoring thread
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        
    def get_scan_results(self, task_id: str) -> Optional[BurpScanResult]:
        """Get scan results by task ID"""
        # Check active scans
        if task_id in self.active_scans:
            return self.active_scans[task_id]
            
        # Check completed scans
        for result in self.completed_scans:
            if result.task_id == task_id:
                return result
                
        return None
        
    def list_active_scans(self) -> List[BurpScanResult]:
        """List all active scans"""
        return list(self.active_scans.values())
        
    def list_completed_scans(self) -> List[BurpScanResult]:
        """List all completed scans"""
        return self.completed_scans
        

def create_burp_integration(target_url: str, config: Dict = None) -> Optional[BurpScanResult]:
    """Simplified interface for tool chaining integration"""
    
    # Default configuration
    default_config = {
        "host": "127.0.0.1",
        "port": 1337,
        "api_key": None,
        "scan_type": "active",
        "crawl_strategy": "thorough",
        "max_crawl_time": 300,
        "max_audit_time": 600
    }
    
    if config:
        default_config.update(config)
        
    try:
        # Initialize API client
        api = BurpSuiteAPI(
            host=default_config["host"],
            port=default_config["port"],
            api_key=default_config.get("api_key")
        )
        
        # Test connection
        if not api.check_connection():
            logger.warning("Cannot connect to Burp Suite API - ensure Burp Suite Professional is running")
            return None
            
        # Get version info
        version_info = api.get_burp_version()
        logger.info(f"Connected to Burp Suite {version_info.get('burp', 'Unknown Version')}")
        
        # Create scan manager and execute scan
        manager = BurpScanManager(api)
        result = manager.execute_automated_scan(target_url, default_config)
        
        return result
        
    except Exception as e:
        logger.error(f"Burp Suite integration error: {e}")
        return None


# CLI Integration Functions
def print_burp_banner():
    """Print Burp Suite integration banner"""
    print(f"""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                    🔥 BURP SUITE INTEGRATION 🔥                   ║
    ║            Professional Web Application Security Scanning          ║  
    ╚═══════════════════════════════════════════════════════════════════╝
    """)


def check_burp_availability() -> bool:
    """Check if Burp Suite API is available"""
    try:
        api = BurpSuiteAPI()
        return api.check_connection()
    except:
        return False