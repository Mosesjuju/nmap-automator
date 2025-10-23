#!/usr/bin/env python3
"""
Async Scan Engine for NMAP Automator v1.2.0
High-performance asynchronous scanning with intelligent resource management
"""

import asyncio
import aiohttp
import aiofiles
import aiodns
import concurrent.futures
import json
import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, AsyncIterator, Callable, Any
from pathlib import Path
import ipaddress
from urllib.parse import urlparse

from performance_optimizer import (
    performance_optimized, 
    AsyncFileManager, 
    performance_profiler,
    global_cache,
    optimized_executor
)

logger = logging.getLogger(__name__)


@dataclass
class AsyncScanResult:
    """Async scan result container"""
    target: str
    scan_type: str
    status: str
    start_time: float
    end_time: Optional[float] = None
    output: Optional[str] = None
    error: Optional[str] = None
    xml_data: Optional[str] = None
    ports: List[Dict] = None
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
        
    def to_dict(self) -> Dict:
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'duration': self.duration,
            'output': self.output,
            'error': self.error,
            'ports': self.ports or []
        }


class AsyncDNSResolver:
    """Asynchronous DNS resolution with caching"""
    
    def __init__(self, max_concurrent: int = 100):
        self.resolver = aiodns.DNSResolver()
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.cache: Dict[str, str] = {}
        
    @performance_optimized(ttl=3600)  # Cache DNS for 1 hour
    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        if hostname in self.cache:
            return self.cache[hostname]
            
        async with self.semaphore:
            try:
                # Check if it's already an IP address
                ipaddress.ip_address(hostname)
                self.cache[hostname] = hostname
                return hostname
            except ValueError:
                pass
                
            try:
                result = await self.resolver.gethostbyname(hostname, family=2)  # IPv4
                ip_address = result.addresses[0]
                self.cache[hostname] = ip_address
                return ip_address
            except Exception as e:
                logger.warning(f"DNS resolution failed for {hostname}: {e}")
                return None
                
    async def resolve_multiple(self, hostnames: List[str]) -> Dict[str, Optional[str]]:
        """Resolve multiple hostnames concurrently"""
        tasks = [self.resolve_hostname(hostname) for hostname in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        resolved = {}
        for hostname, result in zip(hostnames, results):
            if isinstance(result, Exception):
                resolved[hostname] = None
                logger.warning(f"DNS resolution error for {hostname}: {result}")
            else:
                resolved[hostname] = result
                
        return resolved


class AsyncPortScanner:
    """Asynchronous port scanning engine"""
    
    def __init__(self, max_concurrent: int = 500, timeout: float = 3.0):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
    async def scan_port(self, target: str, port: int) -> Tuple[str, int, bool]:
        """Scan a single port asynchronously"""
        async with self.semaphore:
            try:
                future = asyncio.open_connection(target, port)
                reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return target, port, True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return target, port, False
                
    async def scan_ports_range(self, target: str, ports: List[int]) -> List[Dict]:
        """Scan multiple ports on a target"""
        tasks = [self.scan_port(target, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for result in results:
            if isinstance(result, Exception):
                continue
                
            target_ip, port, is_open = result
            if is_open:
                open_ports.append({
                    'port': port,
                    'state': 'open',
                    'protocol': 'tcp'
                })
                
        return open_ports
        
    async def fast_discovery_scan(self, targets: List[str], 
                                common_ports: List[int] = None) -> Dict[str, List[Dict]]:
        """Fast discovery scan across multiple targets"""
        if common_ports is None:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995]
            
        tasks = []
        for target in targets:
            task = self.scan_ports_range(target, common_ports)
            tasks.append((target, task))
            
        results = {}
        for target, task in tasks:
            try:
                open_ports = await task
                if open_ports:
                    results[target] = open_ports
            except Exception as e:
                logger.error(f"Port scan failed for {target}: {e}")
                
        return results


class AsyncNmapExecutor:
    """Asynchronous Nmap command execution"""
    
    def __init__(self, max_concurrent: int = 10):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.running_scans: Set[str] = set()
        
    async def execute_nmap_command(self, command: List[str], target: str) -> AsyncScanResult:
        """Execute Nmap command asynchronously"""
        scan_id = f"{target}_{int(time.time())}"
        result = AsyncScanResult(
            target=target,
            scan_type="nmap",
            status="running",
            start_time=time.time()
        )
        
        async with self.semaphore:
            self.running_scans.add(scan_id)
            
            try:
                # Execute Nmap command
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                result.end_time = time.time()
                result.output = stdout.decode('utf-8', errors='ignore')
                
                if stderr:
                    result.error = stderr.decode('utf-8', errors='ignore')
                    
                if process.returncode == 0:
                    result.status = "completed"
                    
                    # Parse XML output if available
                    xml_output = None
                    for arg in command:
                        if arg.startswith('-oX'):
                            xml_file = command[command.index(arg) + 1]
                            if os.path.exists(xml_file):
                                xml_output = await AsyncFileManager.read_file(xml_file)
                                result.xml_data = xml_output
                                result.ports = await self._parse_nmap_xml(xml_output)
                            break
                else:
                    result.status = "failed"
                    
            except Exception as e:
                result.end_time = time.time()
                result.status = "error"
                result.error = str(e)
                logger.error(f"Nmap execution failed for {target}: {e}")
            finally:
                self.running_scans.discard(scan_id)
                
        return result
        
    async def _parse_nmap_xml(self, xml_content: str) -> List[Dict]:
        """Parse Nmap XML output for port information"""
        try:
            root = ET.fromstring(xml_content)
            ports = []
            
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    service_elem = port.find('service')
                    service_info = {}
                    if service_elem is not None:
                        service_info = {
                            'name': service_elem.get('name', ''),
                            'product': service_elem.get('product', ''),
                            'version': service_elem.get('version', ''),
                            'extrainfo': service_elem.get('extrainfo', '')
                        }
                        
                    ports.append({
                        'port': int(port_id),
                        'protocol': protocol,
                        'state': state,
                        'service': service_info
                    })
                    
            return ports
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return []
            
    async def batch_execute(self, scan_configs: List[Dict]) -> List[AsyncScanResult]:
        """Execute multiple Nmap scans in batches"""
        tasks = []
        
        for config in scan_configs:
            command = config['command']
            target = config['target']
            task = self.execute_nmap_command(command, target)
            tasks.append(task)
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Batch execution error: {result}")
            else:
                valid_results.append(result)
                
        return valid_results


class AsyncToolChainExecutor:
    """Asynchronous tool chain execution"""
    
    def __init__(self, max_concurrent: int = 5):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
    async def execute_tool(self, tool_config: Dict, target: str, 
                          scan_results: Optional[Dict] = None) -> AsyncScanResult:
        """Execute a security tool asynchronously"""
        result = AsyncScanResult(
            target=target,
            scan_type=tool_config.get('name', 'unknown'),
            status="running",
            start_time=time.time()
        )
        
        async with self.semaphore:
            try:
                command = tool_config['command'].format(target=target)
                
                # Execute tool command
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                timeout = tool_config.get('timeout', 300)
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
                
                result.end_time = time.time()
                result.output = stdout.decode('utf-8', errors='ignore')
                
                if stderr:
                    result.error = stderr.decode('utf-8', errors='ignore')
                    
                result.status = "completed" if process.returncode == 0 else "failed"
                
            except asyncio.TimeoutError:
                result.end_time = time.time()
                result.status = "timeout"
                result.error = f"Tool execution timed out after {timeout} seconds"
                
            except Exception as e:
                result.end_time = time.time()
                result.status = "error"
                result.error = str(e)
                logger.error(f"Tool execution failed: {e}")
                
        return result
        
    async def execute_tool_chain(self, tool_configs: List[Dict], target: str,
                               scan_results: Optional[Dict] = None) -> List[AsyncScanResult]:
        """Execute multiple tools in a chain"""
        results = []
        
        for tool_config in tool_configs:
            # Check if tool should be triggered based on previous results
            if self._should_trigger_tool(tool_config, scan_results):
                result = await self.execute_tool(tool_config, target, scan_results)
                results.append(result)
                
                # Update scan_results with new information
                if scan_results is not None and result.status == "completed":
                    scan_results[tool_config['name']] = result.to_dict()
                    
        return results
        
    def _should_trigger_tool(self, tool_config: Dict, scan_results: Optional[Dict]) -> bool:
        """Determine if tool should be triggered based on triggers"""
        if not scan_results:
            return True
            
        triggers = tool_config.get('triggers', [])
        if not triggers:
            return True
            
        for trigger in triggers:
            if trigger in scan_results:
                return True
                
        return False


class AsyncWebScanner:
    """Asynchronous web application scanning"""
    
    def __init__(self, max_concurrent: int = 20, timeout: int = 10):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
    async def check_web_service(self, target: str, port: int, https: bool = False) -> Dict:
        """Check if web service is running on target:port"""
        scheme = "https" if https else "http"
        url = f"{scheme}://{target}:{port}"
        
        async with self.semaphore:
            try:
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as response:
                        content = await response.text(encoding='utf-8', errors='ignore')
                        
                        return {
                            'url': url,
                            'status_code': response.status,
                            'headers': dict(response.headers),
                            'content_length': len(content),
                            'server': response.headers.get('Server', ''),
                            'title': self._extract_title(content),
                            'technologies': await self._detect_technologies(response, content),
                            'accessible': True
                        }
                        
            except Exception as e:
                return {
                    'url': url,
                    'accessible': False,
                    'error': str(e)
                }
                
    def _extract_title(self, content: str) -> str:
        """Extract page title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else ""
        except:
            return ""
            
    async def _detect_technologies(self, response, content: str) -> List[str]:
        """Detect web technologies from headers and content"""
        technologies = []
        
        # Server header
        server = response.headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'iis' in server:
            technologies.append('IIS')
            
        # X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        if 'asp.net' in powered_by:
            technologies.append('ASP.NET')
            
        # Content analysis
        content_lower = content.lower()
        if 'wordpress' in content_lower:
            technologies.append('WordPress')
        if 'drupal' in content_lower:
            technologies.append('Drupal')
        if 'joomla' in content_lower:
            technologies.append('Joomla')
            
        return technologies
        
    async def scan_web_services(self, web_targets: List[Tuple[str, int]]) -> List[Dict]:
        """Scan multiple web services concurrently"""
        tasks = []
        
        for target, port in web_targets:
            # Try both HTTP and HTTPS
            tasks.append(self.check_web_service(target, port, https=False))
            if port in [443, 8443]:
                tasks.append(self.check_web_service(target, port, https=True))
                
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        web_services = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Web scan error: {result}")
            elif result.get('accessible'):
                web_services.append(result)
                
        return web_services


class AsyncScanEngine:
    """Main asynchronous scanning engine"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.dns_resolver = AsyncDNSResolver(max_concurrent=100)
        self.port_scanner = AsyncPortScanner(max_concurrent=500)
        self.nmap_executor = AsyncNmapExecutor(max_concurrent=10)
        self.tool_executor = AsyncToolChainExecutor(max_concurrent=5)
        self.web_scanner = AsyncWebScanner(max_concurrent=20)
        
        # Performance tracking
        self.scan_metrics = []
        
    async def discover_targets(self, targets: List[str]) -> Dict[str, str]:
        """Discover and resolve target hosts"""
        logger.info(f"Resolving {len(targets)} targets...")
        
        metrics = performance_profiler.start_profiling("target_discovery")
        
        try:
            resolved = await self.dns_resolver.resolve_multiple(targets)
            valid_targets = {host: ip for host, ip in resolved.items() if ip is not None}
            
            logger.info(f"Successfully resolved {len(valid_targets)}/{len(targets)} targets")
            return valid_targets
            
        finally:
            performance_profiler.end_profiling(metrics)
            
    async def fast_port_discovery(self, targets: Dict[str, str]) -> Dict[str, List[Dict]]:
        """Perform fast port discovery on targets"""
        logger.info(f"Starting fast port discovery on {len(targets)} targets...")
        
        metrics = performance_profiler.start_profiling("port_discovery")
        
        try:
            target_ips = list(targets.values())
            results = await self.port_scanner.fast_discovery_scan(target_ips)
            
            # Map back to original hostnames
            hostname_results = {}
            for hostname, ip in targets.items():
                if ip in results:
                    hostname_results[hostname] = results[ip]
                    
            logger.info(f"Port discovery completed - found services on {len(hostname_results)} targets")
            return hostname_results
            
        finally:
            performance_profiler.end_profiling(metrics)
            
    async def detailed_nmap_scan(self, targets: Dict[str, str], 
                               port_results: Dict[str, List[Dict]],
                               nmap_args: List[str]) -> List[AsyncScanResult]:
        """Perform detailed Nmap scans on discovered services"""
        logger.info(f"Starting detailed Nmap scans...")
        
        metrics = performance_profiler.start_profiling("nmap_scan")
        
        try:
            scan_configs = []
            
            for hostname, ports_data in port_results.items():
                if not ports_data:
                    continue
                    
                # Build port list
                port_list = [str(port['port']) for port in ports_data]
                port_string = ','.join(port_list)
                
                # Build Nmap command
                timestamp = int(time.time())
                output_base = f"nmap_results/{hostname}_{timestamp}"
                os.makedirs("nmap_results", exist_ok=True)
                
                command = [
                    "nmap",
                    "-p", port_string,
                    "-oN", f"{output_base}.nmap",
                    "-oX", f"{output_base}.xml"
                ] + nmap_args + [targets[hostname]]
                
                scan_configs.append({
                    'command': command,
                    'target': hostname
                })
                
            results = await self.nmap_executor.batch_execute(scan_configs)
            
            logger.info(f"Completed {len(results)} detailed Nmap scans")
            return results
            
        finally:
            performance_profiler.end_profiling(metrics)
            
    async def execute_tool_chains(self, targets: Dict[str, str],
                                scan_results: List[AsyncScanResult],
                                tool_configs: List[Dict]) -> List[AsyncScanResult]:
        """Execute security tool chains on scan results"""
        if not tool_configs:
            return []
            
        logger.info(f"Executing tool chains on {len(targets)} targets...")
        
        metrics = performance_profiler.start_profiling("tool_chain_execution")
        
        try:
            all_results = []
            
            # Convert scan results to dictionary format for trigger checking
            scan_data = {}
            for result in scan_results:
                if result.status == "completed" and result.ports:
                    for port_info in result.ports:
                        service_name = port_info.get('service', {}).get('name', '')
                        if service_name:
                            scan_data[service_name] = True
                            
            # Execute tool chains for each target
            for hostname in targets:
                tool_results = await self.tool_executor.execute_tool_chain(
                    tool_configs, hostname, scan_data
                )
                all_results.extend(tool_results)
                
            logger.info(f"Tool chain execution completed - {len(all_results)} tools executed")
            return all_results
            
        finally:
            performance_profiler.end_profiling(metrics)
            
    async def scan_web_applications(self, targets: Dict[str, str],
                                  port_results: Dict[str, List[Dict]]) -> List[Dict]:
        """Scan discovered web applications"""
        logger.info("Scanning web applications...")
        
        metrics = performance_profiler.start_profiling("web_application_scan")
        
        try:
            web_targets = []
            
            for hostname, ports_data in port_results.items():
                for port_info in ports_data:
                    port = port_info['port']
                    # Check for common web ports
                    if port in [80, 443, 8080, 8443, 8000, 8001, 3000, 9000]:
                        web_targets.append((targets[hostname], port))
                        
            if web_targets:
                web_results = await self.web_scanner.scan_web_services(web_targets)
                logger.info(f"Found {len(web_results)} accessible web services")
                return web_results
            else:
                logger.info("No web services detected")
                return []
                
        finally:
            performance_profiler.end_profiling(metrics)
            
    async def comprehensive_scan(self, targets: List[str], 
                               nmap_args: List[str] = None,
                               tool_configs: List[Dict] = None,
                               include_web_scan: bool = True) -> Dict:
        """Perform comprehensive asynchronous scan"""
        start_time = time.time()
        
        logger.info(f"Starting comprehensive async scan of {len(targets)} targets")
        
        # Set defaults
        nmap_args = nmap_args or ["-sV", "-sC"]
        tool_configs = tool_configs or []
        
        results = {
            'scan_start': start_time,
            'targets_input': targets,
            'targets_resolved': {},
            'port_discovery': {},
            'nmap_results': [],
            'tool_results': [],
            'web_results': [],
            'performance_metrics': {},
            'errors': []
        }
        
        try:
            # Phase 1: Target Discovery
            resolved_targets = await self.discover_targets(targets)
            results['targets_resolved'] = resolved_targets
            
            if not resolved_targets:
                logger.error("No targets could be resolved")
                return results
                
            # Phase 2: Fast Port Discovery
            port_results = await self.fast_port_discovery(resolved_targets)
            results['port_discovery'] = port_results
            
            # Phase 3: Detailed Nmap Scanning
            if port_results:
                nmap_results = await self.detailed_nmap_scan(
                    resolved_targets, port_results, nmap_args
                )
                results['nmap_results'] = [r.to_dict() for r in nmap_results]
                
                # Phase 4: Tool Chain Execution
                if tool_configs:
                    tool_results = await self.execute_tool_chains(
                        resolved_targets, nmap_results, tool_configs
                    )
                    results['tool_results'] = [r.to_dict() for r in tool_results]
                    
                # Phase 5: Web Application Scanning
                if include_web_scan:
                    web_results = await self.scan_web_applications(
                        resolved_targets, port_results
                    )
                    results['web_results'] = web_results
                    
        except Exception as e:
            logger.error(f"Comprehensive scan error: {e}")
            results['errors'].append(str(e))
            
        finally:
            # Performance summary
            results['scan_end'] = time.time()
            results['scan_duration'] = results['scan_end'] - start_time
            results['performance_metrics'] = performance_profiler.get_performance_summary()
            
            logger.info(f"Comprehensive scan completed in {results['scan_duration']:.2f} seconds")
            
        return results
        
    async def save_results(self, results: Dict, output_dir: str = "async_scan_results"):
        """Save scan results asynchronously"""
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = int(time.time())
        results_file = f"{output_dir}/comprehensive_scan_{timestamp}.json"
        
        await AsyncFileManager.write_json(results_file, results)
        logger.info(f"Results saved to {results_file}")


# Convenience functions for easy integration
async def async_quick_scan(targets: List[str], ports: List[int] = None) -> Dict:
    """Quick asynchronous port scan"""
    engine = AsyncScanEngine()
    
    resolved = await engine.discover_targets(targets)
    if not resolved:
        return {}
        
    if ports:
        results = {}
        for hostname, ip in resolved.items():
            port_results = await engine.port_scanner.scan_ports_range(ip, ports)
            if port_results:
                results[hostname] = port_results
        return results
    else:
        return await engine.fast_port_discovery(resolved)


async def async_nmap_scan(targets: List[str], nmap_args: List[str]) -> List[Dict]:
    """Asynchronous Nmap scanning"""
    engine = AsyncScanEngine()
    
    resolved = await engine.discover_targets(targets)
    if not resolved:
        return []
        
    scan_configs = []
    for hostname, ip in resolved.items():
        timestamp = int(time.time())
        output_base = f"nmap_results/{hostname}_{timestamp}"
        os.makedirs("nmap_results", exist_ok=True)
        
        command = [
            "nmap",
            "-oN", f"{output_base}.nmap",
            "-oX", f"{output_base}.xml"
        ] + nmap_args + [ip]
        
        scan_configs.append({
            'command': command,
            'target': hostname
        })
        
    results = await engine.nmap_executor.batch_execute(scan_configs)
    return [r.to_dict() for r in results]


# Example usage
if __name__ == "__main__":
    async def main():
        targets = ["scanme.nmap.org", "testphp.vulnweb.com"]
        
        engine = AsyncScanEngine()
        results = await engine.comprehensive_scan(
            targets=targets,
            nmap_args=["-sV", "-sC", "--script", "vuln"],
            include_web_scan=True
        )
        
        await engine.save_results(results)
        print(f"Scan completed - found services on {len(results['port_discovery'])} targets")
        
    asyncio.run(main())