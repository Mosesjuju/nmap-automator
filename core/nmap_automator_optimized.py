#!/usr/bin/env python3
"""
NMAP Automator v1.2.1 - Performance Optimized Edition
Enhanced with async processing and resource optimization
"""

import argparse
import os
import sys
import logging

# Define logger for the module
logger = logging.getLogger(__name__)

# Import and initialize profiler from performance_optimizer
try:
    from tools.performance_optimizer import profiler
except ImportError:
    profiler = None
import time
import subprocess
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import itertools
from colorama import Fore, Style, init
        #     # queue.task_done()
        #     continue
        # try:
        #     # Use async mode for better performance if enabled
        #     # if async_mode:
        #     #     # Run async scan in thread pool
        #     #     # future = executor.submit_io_task(_run_async_scan, cmd, target, grok_key, tool_chain_config, burp_config)
        #     #     result = future.result(timeout=3600)
        #     # else:
        #     #     # Traditional synchronous execution with optimizations
        #     #     # result = _run_sync_scan(cmd, target, grok_key, tool_chain_config, burp_config)
        #     # if result:
        #     #     logger.info(f"✅ Scan completed successfully for {target}")
        #     # else:
        #     #     logger.warning(f"⚠️ Scan completed with issues for {target}")
        # except Exception as e:
        #     logger.error(f"❌ Scan failed for {target}: {e}")
        # finally:
        #     # Update performance metrics
        #     # final_metrics = profiler.end_profiling(scan_metrics)
        #     # logger.debug(f"Scan metrics for {target}: {final_metrics.duration:.2f}s, "
        #     #             f"Memory: {final_metrics.memory_usage_mb:.1f}MB")
        #     # queue.task_done()
# )
# from performance_logger import performance_logger, PerformanceContext, track_performance  # unresolved import
# from async_scan_engine import AsyncScanEngine, async_quick_scan, async_nmap_scan  # unresolved import

# Evasion and traffic analysis imports
# from evasion_profiles import (
#     EvasionProfileManager,
#     TrafficAnalysisCounter,
#     list_evasion_profiles,
#     apply_evasion_profile
# )

# Initialize colorama for cross-platform colored output

init(autoreset=True)

__version__ = "1.2.1"

# Configure performance-optimized logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')
                    # if cached_result:
                    #     return cached_result  # undefined

# Global performance profiler and smart cache manager
profiler = None  # PerformanceProfiler()  # undefined
executor = None  # OptimizedExecutor()  # undefined

# Initialize smart cache manager for enhanced performance
try:
    smart_cache_manager_func = getattr(sys.modules.get('performance_optimizer'), 'smart_cache_manager', None)
    if smart_cache_manager_func:
        cache_manager = smart_cache_manager_func()
        smart_caching_available = True
        
        # Smart cache logging
        logger.info("🧠 Smart Caching System Active")
        initial_stats = cache_manager.get_analytics()
        logger.info(f"   Cache Performance: {initial_stats['performance']['hit_rate']} hit rate")
        logger.info(f"   Memory Usage: {initial_stats['size_metrics']['memory_mb']}")
    else:
        smart_caching_available = False
        logger.info("📦 Basic caching system active")
except Exception as e:
    smart_caching_available = False
    logger.info(f"📦 Basic caching system active (smart cache unavailable: {e})")


 # @performance_optimized(ttl=300, smart_cache=True)  # undefined decorator
def check_nmap_available():
    """Return path to nmap executable or None if not found with smart caching."""
    from shutil import which
    result = which("nmap")
    logger.debug(f"NMAP availability check: {'✅' if result else '❌'}")
    return result


 # @performance_optimized(ttl=300, smart_cache=True)  # undefined decorator
def check_masscan_available():
    """Return path to masscan executable or None if not found with smart caching."""
    from shutil import which
    result = which("masscan")
    logger.debug(f"Masscan availability check: {'✅' if result else '❌'}")
    return result


def run_masscan_discovery(target, output_file, rate=1000, ports="1-65535"):
    """Run masscan for fast port discovery with performance monitoring"""
    import socket
    import os
    
    # metrics = profiler.start_profiling("masscan_discovery")  # undefined

    # with PerformanceContext("masscan", target, {"rate": rate, "ports": ports}):  # undefined
    try:
            # Resolve hostname to IP if needed (masscan prefers IPs)
            try:
                resolved_target = socket.gethostbyname(target)
                if resolved_target != target:
                    print(f"🔍 Resolved {target} → {resolved_target}")
                    # performance_logger.log_event("hostname_resolved", "masscan", target, {"resolved_ip": resolved_target})  # undefined
            except socket.gaierror:
                resolved_target = target  # Use original if resolution fails

            # Check if we need sudo
            cmd = []
            if os.geteuid() != 0:  # Not running as root
                cmd = ["sudo", "masscan"]
            else:
                cmd = ["masscan"]

            cmd.extend([
                resolved_target,
                "-p", ports,
                "--rate", str(rate),
                "-oG", output_file,
                "--wait", "3"
            ])

            logger.info(f"Running optimized masscan discovery: {' '.join(cmd)}")

            # Use optimized executor for better resource management
            # future = executor.submit_io_task(
            #     subprocess.run, cmd,
            #     capture_output=True, text=True, timeout=300
            # )
            # process = future.result(timeout=310)
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if process.returncode == 0:
                result = parse_masscan_output(output_file)
                # profiler.end_profiling(metrics)  # undefined
                return result
            else:
                error_msg = process.stderr.strip()
                if "permission denied" in error_msg or "need to sudo" in error_msg:
                    print("⚠️ Masscan requires root privileges. Falling back to nmap discovery...")
                    logger.warning("Masscan permission denied, falling back to nmap")
                else:
                    logger.error(f"Masscan failed: {error_msg}")
                return []
    except subprocess.TimeoutExpired:
        logger.error("Masscan timed out after 300 seconds")
        return []
    except Exception as e:
        logger.error(f"Error running masscan: {e}")
        return []
        # finally:
        #     profiler.end_profiling(metrics)  # undefined


 # @performance_optimized(ttl=600)  # undefined decorator
def parse_masscan_output(output_file):
    """Parse masscan grepable output to extract open ports with caching"""
    open_ports = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                # Masscan format: Timestamp: 1761215754   Host: 45.33.32.156 ()   Ports: 22/open/tcp//ssh//
                if "Host:" in line and "Ports:" in line:
                    parts = line.split("Ports:")
                    if len(parts) > 1:
                        port_info = parts[1].strip()
                        # Extract port number (first part before /)
                        port = port_info.split("/")[0].strip()
                        if port.isdigit():
                            open_ports.append(port)
        
        logger.info(f"Masscan found {len(open_ports)} open ports")
        if open_ports:
            ports_list = sorted(set(open_ports), key=int)  # Remove duplicates and sort
            print(f"🎯 Masscan discovered {len(ports_list)} open ports: {', '.join(ports_list)}")
            return ports_list
        return []
        
    except Exception as e:
        logger.error(f"Error parsing masscan output: {e}")
        return []


 # @performance_optimized(ttl=600, smart_cache=True)  # undefined decorator
def build_nmap_command(target, ports=None, scan_type="-sV", extra_args=None, output_basename=None, xml=False, evasion_profile=None):
    """Build nmap command with performance optimizations and smart caching"""
    start_time = time.time()
    
    args = ["nmap"]
    
    # Add performance optimizations to nmap (unless overridden by evasion)
    if not evasion_profile:
        optimal_timing = "-T4"  # Aggressive timing for better performance
        if scan_type and optimal_timing not in scan_type:
            args.append(optimal_timing)
    
    if scan_type:
        args.extend(scan_type.split())
    if ports:
        args.extend(["-p", ports])
    if extra_args:
        args.extend(extra_args.split())

    # output files
    if output_basename:
        txt_out = f"{output_basename}.txt"
        args.extend(["-oN", txt_out])
        if not xml:
            xml_out = f"{output_basename}.xml"
            args.extend(["-oX", xml_out])

    args.append(target)
    
    # Apply evasion profile if specified
    if evasion_profile:
        # evasion_manager = EvasionProfileManager()  # undefined
        # args = evasion_manager.build_evasion_command(args, evasion_profile, target)  # undefined
        # logger.info(f"🥷 Applied evasion profile '{evasion_profile}' to command")
        pass
    
    # Log command building performance
    build_time = time.time() - start_time
    if build_time > 0.1:  # Log if building takes more than 100ms
        logger.debug(f"Command building took {build_time:.3f}s for {target}")
    
    return args


 # @performance_optimized(ttl=3600, smart_cache=True)  # undefined decorator
def parse_nmap_xml(xml_file):
    """Parse nmap XML output with enhanced performance and smart caching"""
    try:
        # Use pathlib for better file handling
        xml_path = Path(xml_file)
        if not xml_path.exists():
            logger.error(f"XML file not found: {xml_file}")
            return None
            
        # Check file modification time for cache invalidation
        file_mtime = xml_path.stat().st_mtime
        cache_key = f"xml_parse:{xml_file}:{file_mtime}"
        
        # Try to get from cache with file modification check
        if smart_caching_available:
            try:
                # cached_result = global_cache.get(cache_key)  # undefined
                if cached_result:
                    logger.debug(f"🚀 Smart cache HIT for XML parsing: {xml_file}")
                    return cached_result
            except:
                pass  # Fallback to normal parsing
            
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        interesting_findings = {
            'open_ports': [],
            'vulnerabilities': [],
            'services': [],
            'cves': [],
            'script_outputs': {},
            'host_info': {}
        }
        
        # Enhanced host information extraction
        for host in root.findall('.//host'):
            # Get host addresses
            addresses = []
            for address in host.findall('address'):
                addr_type = address.get('addrtype')
                addr = address.get('addr')
                addresses.append({'type': addr_type, 'addr': addr})
            
            # Get hostnames
            hostnames = []
            for hostname in host.findall('.//hostname'):
                hostnames.append(hostname.get('name'))
                
            interesting_findings['host_info'] = {
                'addresses': addresses,
                'hostnames': hostnames,
                'status': host.find('status').get('state') if host.find('status') is not None and hasattr(host.find('status'), 'get') else 'unknown'
            }
        
        # Check for open ports with enhanced service detection
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                port_id = port.get('portid')
                protocol = port.get('protocol', 'tcp')
                
                service_info = {'name': 'unknown', 'product': '', 'version': '', 'extrainfo': ''}
                service = port.find('service')
                if service is not None:
                    service_info.update({
                        'name': service.get('name', 'unknown'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'extrainfo': service.get('extrainfo', ''),
                        'method': service.get('method', ''),
                        'confidence': service.get('conf', '0')
                    })
                
                port_data = {
                    'port': port_id,
                    'protocol': protocol,
                    'service': service_info
                }
                
                interesting_findings['open_ports'].append((port_id, service_info['name']))
                
                # Enhanced service categorization
                service_name = service_info['name'].lower()
                if service_name in ['http', 'https', 'ftp', 'ssh', 'telnet', 'mysql', 'mssql', 
                                  'postgresql', 'mongodb', 'redis', 'elasticsearch', 'smtp', 'pop3', 'imap']:
                    interesting_findings['services'].append(service_name)
        
        # Enhanced vulnerability and script output processing
        for script in root.findall('.//script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            
            # Store all script outputs for comprehensive analysis
            interesting_findings['script_outputs'][script_id] = output
            
            # Enhanced vulnerability detection
            if any(vuln_keyword in script_id.lower() for vuln_keyword in 
                  ['vuln', 'exploit', 'cve', 'dos', 'backdoor', 'malware']):
                interesting_findings['vulnerabilities'].append({
                    'script': script_id,
                    'output': output
                })
                
                # Enhanced CVE extraction with better regex
                cves = re.findall(r'CVE[-_](\d{4})[-_](\d{4,7})', output, re.IGNORECASE)
                for year, number in cves:
                    cve_id = f"CVE-{year}-{number}"
                    interesting_findings['cves'].append(cve_id)
        
        # Remove duplicate CVEs and services
        interesting_findings['cves'] = list(set(interesting_findings['cves']))
        interesting_findings['services'] = list(set(interesting_findings['services']))
                
        return interesting_findings
        
    except ET.ParseError as e:
        logger.error(f"XML parsing error in {xml_file}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error parsing XML file {xml_file}: {e}")
        return None


 # @profiler.profile_function  # undefined
def auto_escalate_scan(target, initial_findings, current_args):
    """Auto-escalate scans based on findings with performance monitoring"""
    if not initial_findings or not initial_findings.get('services'):
        return None
        
    escalation_rules = {
        'web_services': {
            'triggers': ['http', 'https'],
            'additional_args': '--script http-enum,http-vuln-*,ssl-enum-ciphers'
        },
        'database_services': {
            'triggers': ['mysql', 'mssql', 'postgresql', 'mongodb'],
            'additional_args': '--script *-info,*-enum,*-vuln'
        },
        'remote_access': {
            'triggers': ['ssh', 'telnet', 'rdp', 'vnc'],
            'additional_args': '--script ssh-auth-methods,ssh-vuln-*,telnet-encryption'
        },
        'file_services': {
            'triggers': ['ftp', 'smb', 'nfs'],
            'additional_args': '--script ftp-anon,smb-enum-*,nfs-*'
        }
    }
    
    detected_services = set(initial_findings.get('services', []))
    
    for category, rule in escalation_rules.items():
        triggers = set(rule['triggers'])
        if triggers.intersection(detected_services):
            logger.info(f"🎯 Auto-escalating scan for {category} services on {target}")
            
            # Build escalated command
            escalated_args = current_args.copy()
            if rule['additional_args'] not in ' '.join(escalated_args):
                escalated_args.extend(rule['additional_args'].split())
                
    # ...existing code...
    """Enhanced worker function with performance optimizations and async support"""
    
    import itertools
    
    while True:
    # item = queue.get()  # queue may be undefined
        if item is None:
            break
            
        cmd, target = item
        
        # Performance metrics for this scan
        scan_metrics = profiler.start_profiling(f"scan_{target}")
        
        logger.info(f"⚡ Optimized scan starting: {' '.join(cmd)}")
        
    # if dry_run:  # dry_run may be undefined
            # print(f"🔍 DRY RUN: {' '.join(cmd)}")  # undefined
            # queue.task_done()  # queue may be undefined
            # continue
            # try:
            #     # Use async mode for better performance if enabled
            #     # if async_mode:
            #     #     # Run async scan in thread pool
            #     #     # future = executor.submit_io_task(_run_async_scan, cmd, target, grok_key, tool_chain_config, burp_config)
            #     #     result = future.result(timeout=3600)
            #     # else:
            #     #     # Traditional synchronous execution with optimizations
            #     #     # result = _run_sync_scan(cmd, target, grok_key, tool_chain_config, burp_config)
            #     # if result:
            #     #     logger.info(f"✅ Scan completed successfully for {target}")
            #     # else:
            #     #     logger.warning(f"⚠️ Scan completed with issues for {target}")
            # except Exception as e:
            #     logger.error(f"❌ Scan failed for {target}: {e}")
            # finally:
            #     # Update performance metrics
            #     # final_metrics = profiler.end_profiling(scan_metrics)
            #     # logger.debug(f"Scan metrics for {target}: {final_metrics.duration:.2f}s, "
            #     #             f"Memory: {final_metrics.memory_usage_mb:.1f}MB")
            #     # queue.task_done()


def _run_async_scan(cmd, target, grok_key, tool_chain_config, burp_config):
    """Run asynchronous scan wrapper"""
    try:
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def async_scan_wrapper():
            # Convert command to async scan
            if '--async-fast' in cmd:
                # Use async fast scan
                targets = [target]
                results = await async_quick_scan(targets)
                return process_async_results(results, target, grok_key, tool_chain_config, burp_config)
            else:
                # Use async nmap scan
                nmap_args = [arg for arg in cmd if not arg.startswith('-')]
                results = await async_nmap_scan([target], nmap_args)
                return process_async_results(results, target, grok_key, tool_chain_config, burp_config)
        
        return loop.run_until_complete(async_scan_wrapper())
        
    finally:
        # loop.close()  # loop may be unbound
        pass


def _run_sync_scan(cmd, target, grok_key, tool_chain_config, burp_config):
    """Run synchronous scan with performance optimizations"""
    import itertools

    # Start subprocess with optimized settings
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, bufsize=8192)  # Larger buffer for better I/O

    # Enhanced spinner with performance info
    spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'])
    start_time = time.time()

    while proc.poll() is None:
        elapsed = time.time() - start_time
            # memory_usage = profiler.resource_monitor.get_memory_usage()  # undefined
            memory_usage = 0
            time.sleep(0.2)

    print()  # New line after completion

    # Get output after process completes
    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        # logger.error(f"nmap returned code {proc.returncode} for {target}: {stderr.strip()}")
        return False
    else:
        # logger.info(f"✅ Scan completed for {target}")
        # Process results with performance monitoring
        return process_scan_results(cmd, target, grok_key, tool_chain_config, burp_config)
    """Run synchronous scan with performance optimizations"""
    import itertools
    
    # Start subprocess with optimized settings
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                           text=True, bufsize=8192)  # Larger buffer for better I/O
    
    # Enhanced spinner with performance info
    spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'])
    start_time = time.time()
    
    while proc.poll() is None:
        elapsed = time.time() - start_time
    # memory_usage = profiler.resource_monitor.get_memory_usage()  # undefined
    memory_usage = 0
        
      # ...existing code...
        time.sleep(0.2)
        
    print()  # New line after completion
    
    # Get output after process completes
    stdout, stderr = proc.communicate()
    
    if proc.returncode != 0:
    # logger.error(f"nmap returned code {proc.returncode} for {target}: {stderr.strip()}")
        return False
    else:
    # logger.info(f"✅ Scan completed for {target}")
        
        # Process results with performance monitoring
        return process_scan_results(cmd, target, grok_key, tool_chain_config, burp_config)


def process_async_results(results, target, grok_key, tool_chain_config, burp_config):
    """Process asynchronous scan results"""
    if not results:
        return False
        
    # logger.info(f"📊 Processing async scan results for {target}")
    
    # Convert async results to compatible format
    findings = {
        'open_ports': [],
        'services': [],
        'vulnerabilities': [],
        'cves': []
    }
    
    # Process results based on type
    if isinstance(results, dict):
        for host, ports in results.items():
            if host == target:
                for port_info in ports:
                    port_num = str(port_info['port'])
                    service = port_info.get('service', {}).get('name', 'unknown')
                    findings['open_ports'].append((port_num, service))
                    if service != 'unknown':
                        findings['services'].append(service)
    
    elif isinstance(results, list):
        for result in results:
            if result.get('target') == target and result.get('ports'):
                for port_info in result['ports']:
                    port_num = str(port_info['port'])
                    service = port_info.get('service', {}).get('name', 'unknown')
                    findings['open_ports'].append((port_num, service))
                    if service != 'unknown':
                        findings['services'].append(service)
    
    # Process with existing pipeline
    return _process_findings(findings, target, grok_key, tool_chain_config, burp_config)


@performance_optimized()
def process_scan_results(cmd, target, grok_key, tool_chain_config, burp_config):
    """Process scan results with caching and optimization"""
    
    with PerformanceContext("nmap_processing", target, {"scan_type": "result_processing"}):
        # Find XML output file
        xml_file = None
        for i, arg in enumerate(cmd):
            if arg == '-oX' and i + 1 < len(cmd):
                xml_file = cmd[i + 1]
                break
        
        if not xml_file or not os.path.exists(xml_file):
            logger.warning(f"No XML output found for {target}")
            performance_logger.log_event("scan_warning", "nmap", target, 
                                       {"issue": "no_xml_output"})
            return True  # Still consider successful
        
        # Parse XML with caching
        findings = parse_nmap_xml(xml_file)
        if not findings:
            logger.warning(f"Could not parse scan results for {target}")
            performance_logger.log_event("scan_error", "nmap", target, 
                                       {"issue": "xml_parse_failed"})
            return False
        
        # Log findings count
        performance_logger.log_event("scan_results", "nmap", target, {
            "open_ports": len(findings.get('open_ports', [])),
            "vulnerabilities": len(findings.get('vulnerabilities', [])),
            "xml_file": xml_file
        })
        
        return _process_findings(findings, target, grok_key, tool_chain_config, burp_config, xml_file)


def _process_findings(findings, target, grok_key, tool_chain_config, burp_config, xml_file=None):
    """Process scan findings with AI analysis and tool chaining"""
    
    if not (findings.get('open_ports') or findings.get('vulnerabilities')):
        # logger.info(f"No significant findings for {target}")
        return True
    # logger.info(f"📊 Processing findings for {target}: {len(findings['open_ports'])} open ports, "
    #            f"{len(findings['vulnerabilities'])} potential vulnerabilities")
    
    # AI Analysis with performance optimization
    if findings.get('vulnerabilities') or findings.get('cves'):
        _perform_ai_analysis(findings, target, grok_key, xml_file)
    
    # Tool Chaining with async execution
    if tool_chain_config and tool_chain_config.get('enabled', False):
        _execute_tool_chain(findings, target, tool_chain_config)
    
    # Burp Suite Integration
    if burp_config and burp_config.get('enabled', False):
        _execute_burp_scan(findings, target, burp_config)
    
    return True


@profiler.profile_function  
def _perform_ai_analysis(findings, target, grok_key, xml_file):
    """Perform AI vulnerability analysis with performance monitoring"""
    try:
        logger.info(f"🤖 Starting AI analysis for {target}")
        
        # Initialize analyzer with performance optimization
        if grok_key:
            analyzer = VulnerabilityAnalyzer(grok_api_key=grok_key, use_grok=True)
        else:
            analyzer = VulnerabilityAnalyzer()
        
        # Perform analysis
        if xml_file and os.path.exists(xml_file):
            analysis = analyzer.analyze_vulnerabilities(xml_file)
        else:
            analysis = analyzer.analyze_vulnerabilities(
                findings.get('cves', []),
                findings.get('script_outputs', {})
            )
        
        # Process and log results
        if analysis:
            logger.info("🎯 AI Vulnerability Analysis Results:")
            
            if 'vulnerabilities' in analysis:
                for vuln in analysis['vulnerabilities'][:5]:  # Limit output for performance
                    logger.info(f"  🔴 {vuln.get('description', 'Unknown vulnerability')}")
                    logger.info(f"     Severity: {vuln.get('severity', 'Unknown')}")
                    logger.info(f"     Exploitability: {vuln.get('exploitability', 'Unknown')}")
            
            if 'metasploit_suggestions' in analysis:
                logger.info("⚔️ Metasploit Module Suggestions:")
                for module in analysis['metasploit_suggestions'][:3]:  # Limit for performance
                    logger.info(f"  📦 Module: {module.get('module', 'Unknown')}")
                    if module.get('description'):
                        logger.info(f"     Description: {module['description'][:100]}...")
            
            # Save analysis with async I/O
            analysis_file = f"{xml_file}.analysis.json" if xml_file else f"analysis_{target}_{int(time.time())}.json"
            
            # Use thread pool for file I/O
            future = executor.submit_io_task(_save_json_analysis, analysis_file, analysis)
            future.result(timeout=30)  # 30 second timeout for file save
            
            logger.info(f"📄 Analysis saved to: {analysis_file}")
            
    except Exception as e:
        logger.error(f"❌ AI analysis failed for {target}: {e}")


def _save_json_analysis(filename, data):
    """Save JSON analysis data with error handling"""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save analysis to {filename}: {e}")
        return False


@profiler.profile_function
def _execute_tool_chain(findings, target, tool_chain_config):
    """Execute tool chain with performance optimization"""
    try:
    # logger.info(f"⚡ Starting optimized tool chain for {target}")
        
        from tool_chain import ToolChain
        tool_chain = ToolChain(tool_chain_config.get('config_path', 'tools.config.example.json'))
        
        # Analyze findings for triggers
        triggers = tool_chain.analyze_scan_results({
            'open_ports': findings.get('open_ports', []),
            'services': findings.get('services', []),
            'target_type': 'host'
        })
        
        if triggers:
            logger.info(f"🔗 Tool chain triggers activated: {triggers}")
            
            # Get selected tools
            selected_tools = tool_chain_config.get('selected_tools', None)
            
            # Execute with performance monitoring
            chain_results = tool_chain.execute_tool_chain(target, triggers, selected_tools)
            
            # Process results
            completed_tools = [r for r in chain_results if r.status.value == 'completed']
            failed_tools = [r for r in chain_results if r.status.value == 'failed']
            
            logger.info(f"🔗 Tool chain completed: ✅{len(completed_tools)} successful, ❌{len(failed_tools)} failed")
            
            for result in completed_tools[:5]:  # Limit logging for performance
                logger.info(f"   ✅ {result.tool_name}: {result.output_file}")
                
            if failed_tools:
                for result in failed_tools[:3]:  # Limit error logging
                    logger.warning(f"   ❌ {result.tool_name}: {result.stderr[:100]}...")
        else:
            logger.info(f"🔗 No tool chain triggers activated for {target}")
            
    except Exception as e:
        logger.error(f"❌ Tool chain execution failed for {target}: {e}")


@profiler.profile_function
def _execute_burp_scan(findings, target, burp_config):
    """Execute Burp Suite scan with performance optimization"""
    try:
        # Check for web services
        web_services = [port for port, service in findings.get('open_ports', []) 
                       if service in ['http', 'https']]
        
        if not web_services:
            logger.debug(f"No web services detected for Burp scanning on {target}")
            return
        
        logger.info(f"🔥 Starting optimized Burp Suite scan for {target}")
        
        # Use executor for Burp integration
        future = executor.submit_io_task(_run_burp_scan, findings, target, burp_config)
        result = future.result(timeout=1800)  # 30 minute timeout
        
        if result:
            logger.info(f"🔥 Burp Suite scan completed for {target}")
        else:
            logger.warning(f"🔥 Burp Suite scan had issues for {target}")
            
    except Exception as e:
        logger.error(f"❌ Burp Suite scan failed for {target}: {e}")


def _run_burp_scan(findings, target, burp_config):
    """Run Burp Suite scan in separate thread"""
    try:
        # Determine protocol and construct URLs
        scan_urls = []
        
        for port, service in findings.get('open_ports', []):
            if service in ['http', 'https']:
                protocol = 'https' if service == 'https' or port == '443' else 'http'
                url = f"{protocol}://{target}:{port}"
                scan_urls.append(url)
        
        if not scan_urls:
            return False
        
        # Create Burp integration and execute scan
        burp_manager = create_burp_integration(burp_config)
        
        for url in scan_urls[:3]:  # Limit to 3 URLs for performance
            try:
                scan_id = burp_manager.create_scan(url, burp_config.get('scan_type', 'passive'))
                if scan_id:
                    logger.info(f"🔥 Burp scan created for {url} (ID: {scan_id})")
                    
                    # Add to background monitoring
                    burp_manager.add_to_monitoring(scan_id, url)
                else:
                    logger.warning(f"🔥 Failed to create Burp scan for {url}")
                    
            except Exception as e:
                logger.error(f"🔥 Burp scan creation failed for {url}: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"Burp scan execution error: {e}")
        return False


def load_targets_from_file(file_path):
    """Load targets from file with performance optimization"""
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        logger.info(f"Loaded {len(targets)} targets from {file_path}")
        return targets
    except Exception as e:
        logger.error(f"Error loading targets from {file_path}: {e}")
        return []


def run_scheduled_scan(args, targets, extra_args_str, tool_chain_config, burp_config):
    """Execute scheduled scan with performance optimization"""
    logger.info(f"⏰ Starting scheduled scan of {len(targets)} targets")
    
    # Performance metrics for scheduled scan
    scan_metrics = profiler.start_profiling("scheduled_scan")
    
    try:
        q = Queue()
        optimal_threads = get_optimal_thread_count() if args.threads <= 0 else args.threads
        threads = []
        
        # Use optimized worker with async support
        for _ in range(max(1, optimal_threads)):
            t = threading.Thread(
                # target=optimized_worker,  # may be undefined
                args=(q, args.dry_run, getattr(args, 'grok_key', None), 
                      tool_chain_config, burp_config, args.async_mode), 
                daemon=True
            )
            t.start()
            threads.append(t)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Enhanced progress tracking
        total_targets = len(targets)
        with tqdm(total=total_targets, desc="🎯 Scanning Progress", 
                 bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            
            for idx, target in enumerate(targets):
                pbar.set_description(f"🎯 Scanning {target}")
                
                safe_name = target.replace('/', '_').replace(':', '_')
                basename = os.path.join(args.outdir, f"{safe_name}_{timestamp}")
                
                # Handle masscan fast mode
                if args.masscan_fast and check_masscan_available():
                    # Use masscan discovery first
                    masscan_output = f"{basename}.masscan"
                    open_ports = run_masscan_discovery(target, masscan_output, 
                                                     rate=args.masscan_rate, 
                                                     ports=args.masscan_ports)
                    
                    if open_ports:
                        # Build targeted nmap command with discovered ports
                        port_string = ','.join(open_ports)
                        cmd = build_nmap_command(target, ports=port_string, 
                                               scan_type="", extra_args=extra_args_str,
                                               output_basename=basename, xml=not args.no_xml,
                                               evasion_profile=getattr(args, 'evasion', None))
                    else:
                        # Fallback to regular scan
                        cmd = build_nmap_command(target, ports=args.ports, 
                                               scan_type="", extra_args=extra_args_str,
                                               output_basename=basename, xml=not args.no_xml,
                                               evasion_profile=getattr(args, 'evasion', None))
                else:
                    # Regular nmap command
                    cmd = build_nmap_command(target, ports=args.ports, 
                                           scan_type="", extra_args=extra_args_str,
                                           output_basename=basename, xml=not args.no_xml,
                                           evasion_profile=getattr(args, 'evasion', None))
                
                q.put((cmd, target))
                pbar.update(1)
        
        # Wait for completion
        q.join()
        
        # Stop workers
        for _ in threads:
            q.put(None)
        for t in threads:
            t.join(timeout=5)
            
    finally:
        final_metrics = profiler.end_profiling(scan_metrics)
        logger.info(f"⏰ Scheduled scan completed in {final_metrics.duration:.2f}s")
        
        # Display performance summary
        perf_summary = profiler.get_performance_summary()
        if perf_summary:
            logger.info("📊 Performance Summary:")
            logger.info(f"   Total Operations: {perf_summary.get('total_operations', 0)}")
            logger.info(f"   Cache Hit Rate: {perf_summary.get('cache_statistics', {}).get('hit_rate', 'N/A')}")
            logger.info(f"   Peak Memory: {perf_summary.get('peak_memory_usage_mb', 0):.1f}MB")


@performance_optimized()
def get_performance_report():
    """Generate comprehensive performance report"""
    
    # Get detailed performance summary from new logger
    detailed_summary = performance_logger.get_performance_summary(24)  # Last 24 hours
    
    return {
        'version': __version__,
        'detailed_performance': detailed_summary,
        'legacy_metrics': profiler.get_performance_summary(),
        'cache_stats': global_cache.get_stats(),
        'system_resources': {
            'cpu_count': profiler.resource_monitor.get_cpu_count(),
            'memory_total_gb': profiler.resource_monitor.process.memory_info().rss / 1024**3,
            'optimal_threads': get_optimal_thread_count()
        },
        'recommendations': profiler.resource_monitor.suggest_optimization()
    }


def main():
    """Main function with performance optimization enhancements"""
    
    # Performance monitoring
    main_metrics = profiler.start_profiling("main_execution")
    
    # Initialize performance logging
    performance_logger.log_event("application_start", "nmap_automator", "system", 
                                {"version": "1.2.1", "mode": "optimized"})
    
    try:
        nmap_path = check_nmap_available()
        if not nmap_path:
            print(f"{Fore.RED}Error: nmap not found in PATH. Please install nmap.{Style.RESET_ALL}")
            performance_logger.log_event("application_error", "nmap_automator", "system", 
                                       {"error": "nmap_not_found"})
            sys.exit(2)

        print(f"{Fore.GREEN}NMAP AUTOMATOR v{__version__} - Performance Optimized Edition{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚡ Enhanced with async processing, intelligent caching, and resource optimization{Style.RESET_ALL}")
        
        parser = argparse.ArgumentParser(
            description=f'NMAP Automator v{__version__} - Performance Optimized Security Scanner',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog='''
Examples:
  %(prog)s scanme.nmap.org                    # Basic scan
  %(prog)s --masscan-fast 192.168.1.0/24     # Ultra-fast masscan discovery
  %(prog)s --async-mode --chain-tools target.com  # Async with tool chaining
  %(prog)s --lightning --async-mode subnet   # Lightning fast async scan
  %(prog)s --performance-report              # Show performance metrics
  %(prog)s --optimize-config                 # Auto-optimize configuration
'''
        )

        # Enhanced argument groups with performance options
        tgroup = parser.add_argument_group('🎯 Target Selection')
        tgroup.add_argument('targets', nargs='*', help='Target hosts/networks to scan')
        tgroup.add_argument('-iL', metavar='FILE', help='Read targets from file')
        tgroup.add_argument('-iR', type=int, metavar='NUM', help='Scan random targets')

        hgroup = parser.add_argument_group('🔍 Host Discovery')
        hgroup.add_argument('-sL', action='store_true', help='List scan - simply list targets to scan')
        hgroup.add_argument('-sn', action='store_true', help='Ping scan - disable port scan')
        hgroup.add_argument('-Pn', action='store_true', help='Treat all hosts as online -- skip host discovery')
        hgroup.add_argument('-n', action='store_true', help="Never do DNS resolution")
        hgroup.add_argument('-R', action='store_true', help="Always resolve [default: sometimes]")
        hgroup.add_argument('--traceroute', action='store_true', help='Trace hop path to each host')

        sgroup = parser.add_argument_group('⚔️ Scan Techniques')
        sgroup.add_argument('-sS', action='store_true', help='TCP SYN scan')
        sgroup.add_argument('-sT', action='store_true', help='Connect scan')
        sgroup.add_argument('-sA', action='store_true', help='ACK scan')
        sgroup.add_argument('-sU', action='store_true', help='UDP scan')
        sgroup.add_argument('-sN', action='store_true', help='TCP Null scan')
        sgroup.add_argument('-sF', action='store_true', help='FIN scan')
        sgroup.add_argument('-sX', action='store_true', help='Xmas scan')

        pgroup = parser.add_argument_group('🚪 Port Specification')
        pgroup.add_argument('-p', dest='ports', help='Only scan specified ports Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9')

        # Performance and Speed presets
        speedgroup = parser.add_argument_group('🚀 Performance & Speed Presets')
        speedgroup.add_argument('--masscan-fast', action='store_true', 
                              help='🏃 MASSCAN FAST: Use masscan for ultra-fast discovery then targeted nmap')
        speedgroup.add_argument('--masscan-rate', type=int, default=1000, 
                              help='Masscan packet rate (default: 1000)')
        speedgroup.add_argument('--masscan-ports', default='1-65535', 
                              help='Masscan port range (default: 1-65535)')
        speedgroup.add_argument('--async-mode', action='store_true', 
                              help='⚡ Enable asynchronous scanning for better performance')
        speedgroup.add_argument('--fast-scan', action='store_true', 
                              help='🎯 FAST: -T4 -F --top-ports 100 -Pn')
        speedgroup.add_argument('--lightning', action='store_true', 
                              help='⚡ LIGHTNING: -T5 --top-ports 20 -Pn -n --min-rate 1000')
        speedgroup.add_argument('--stealth-fast', action='store_true', 
                              help='🥷 STEALTH FAST: -sS -T4 --top-ports 100 -Pn')
        speedgroup.add_argument('--discovery-only', action='store_true', 
                              help='🔍 DISCOVERY: -sn -PE -PP -PS21,22,23,25,53,80,113,443,993,995')
        speedgroup.add_argument('--web-quick', action='store_true', 
                              help='🌐 WEB QUICK: -p 80,443,8080,8443 -sV -T4')
        
        # Performance optimization options
        perfgroup = parser.add_argument_group('⚡ Performance Optimization')
        perfgroup.add_argument('--performance-report', action='store_true', 
                             help='Show comprehensive performance metrics and exit')
        perfgroup.add_argument('--performance-format', choices=['json', 'csv', 'txt'], 
                             default='txt', help='Performance report format (default: txt)')
        perfgroup.add_argument('--optimize-config', action='store_true', 
                             help='Auto-optimize configuration based on system resources')
        perfgroup.add_argument('--cache-clear', action='store_true', 
                             help='Clear performance cache and exit')
        perfgroup.add_argument('--threads', type=int, default=0, 
                             help='Number of threads (0 = auto-optimize based on system)')

        # Traffic Analysis & Evasion Profiles
        evasiongroup = parser.add_argument_group('🥷 Traffic Analysis & Evasion Profiles')
        evasiongroup.add_argument('--evasion', choices=['stealth', 'firewall_evasion', 'ids_evasion', 
                                 'waf_evasion', 'behavioral_evasion', 'fast_evasion', 'apt_stealth'], 
                                help='🥷 Apply evasion profile to bypass security controls')
        evasiongroup.add_argument('--list-evasion', action='store_true', 
                                help='📋 List all available evasion profiles and exit')
        evasiongroup.add_argument('--evasion-info', 
                                help='🔍 Show detailed information about specific evasion profile')
        evasiongroup.add_argument('--custom-decoys', 
                                help='🎭 Custom decoy IP list (comma-separated)')
        evasiongroup.add_argument('--spoof-source', 
                                help='👻 Spoof source IP address (requires raw socket access)')
        evasiongroup.add_argument('--fragment-packets', action='store_true',
                                help='📦 Fragment packets to evade detection')
        evasiongroup.add_argument('--randomize-order', action='store_true',
                                help='🔀 Randomize target scanning order')

        svcgroup = parser.add_argument_group('🔧 Service/Version Detection')
        svcgroup.add_argument('-sV', action='store_true', help='Probe open ports to determine service/version info')
        svcgroup.add_argument('--version-intensity', type=int, metavar='LEVEL', help='Set from 0 (light) to 9 (try all probes)')
        svcgroup.add_argument('--version-light', action='store_true', help='Limit to most likely probes (intensity 2)')
        svcgroup.add_argument('--version-all', action='store_true', help='Try every single probe (intensity 9)')

        scriptgroup = parser.add_argument_group('📜 Script Scan')
        scriptgroup.add_argument('-sC', action='store_true', help='equivalent to --script=default')
        scriptgroup.add_argument('--script', help='<Lua scripts>')
        scriptgroup.add_argument('--script-args', help='<n1=v1,[n2=v2,...]>')

        osgroup = parser.add_argument_group('🖥️ OS Detection')
        osgroup.add_argument('-O', action='store_true', help='Enable OS detection')
        osgroup.add_argument('--osscan-limit', action='store_true', help='Limit OS detection to promising targets')
        osgroup.add_argument('--osscan-guess', action='store_true', help='Guess OS more aggressively')

        timegroup = parser.add_argument_group('⏱️ Timing and Performance')
        timegroup.add_argument('-T', type=int, choices=range(6), metavar='<0-5>', help='Set timing template (higher is faster)')
        timegroup.add_argument('--min-rate', type=int, help='Send packets no slower than <number> per second')
        timegroup.add_argument('--max-rate', type=int, help='Send packets no faster than <number> per second')

        evasiongroup = parser.add_argument_group('🛡️ Firewall/IDS Evasion')
        evasiongroup.add_argument('-f', action='store_true', help='fragment packets')
        evasiongroup.add_argument('-D', help='<decoy1,decoy2[,ME],...>')
        evasiongroup.add_argument('-S', help='<IP_Address>')
        evasiongroup.add_argument('--data-length', type=int, help='<num>')

        outgroup = parser.add_argument_group('📁 Output')
        outgroup.add_argument('-v', dest='verbose', action='count', default=0, help='Increase verbosity level (use -vv or more for greater effect)')
        outgroup.add_argument('-d', dest='debug', action='count', default=0, help='Increase debugging level (use -dd or more for greater effect)')
        outgroup.add_argument('--reason', action='store_true', help='Display the reason a port is in a particular state')
        outgroup.add_argument('--open', action='store_true', help='Only show open (or possibly open) ports')
        outgroup.add_argument('--outdir', default='nmap_results', help='Output directory for scan results')
        outgroup.add_argument('--no-xml', action='store_true', help='Disable XML output generation')

        miscgroup = parser.add_argument_group('🔀 Misc')
        miscgroup.add_argument('-A', action='store_true', help='Enable OS detection, version detection, script scanning, and traceroute')
        miscgroup.add_argument('-6', dest='_6', action='store_true', help='Enable IPv6 scanning')
        miscgroup.add_argument('--dry-run', action='store_true', help='Show commands without executing them')

        # Scheduling and Automation
        schedgroup = parser.add_argument_group('📅 Scheduling & Automation')
        schedgroup.add_argument('--schedule', help='Schedule periodic scans (e.g., "1h" for hourly, "1d" for daily)')

        # Tool Chaining - NEW v1.1.1
        toolgroup = parser.add_argument_group('🔗 Tool Chaining Integration')
        toolgroup.add_argument('--chain-tools', action='store_true', help='🔗 Enable automatic tool chaining based on discovered services')
        toolgroup.add_argument('--list-tools', action='store_true', help='📋 List all available security tools and exit')
        toolgroup.add_argument('--select-tools', help='🎯 Comma-separated list of specific tools to use (e.g., "nikto,dirb,gobuster")')
        toolgroup.add_argument('--tools-config', help='📄 Path to custom tools configuration file (default: tools.config.example.json)')
        toolgroup.add_argument('--tools-parallel', action='store_true', help='⚡ Run tools in parallel for faster execution')
        toolgroup.add_argument('--tools-output', default='tool_results', help='📁 Output directory for tool results')

        # Burp Suite Integration - NEW v1.1.1
        burpgroup = parser.add_argument_group('🔥 Burp Suite Professional Integration')
        burpgroup.add_argument('--burp', action='store_true', help='🔥 Enable Burp Suite automated scanning')
        burpgroup.add_argument('--burp-host', default='127.0.0.1', help='🌐 Burp Suite host (default: 127.0.0.1)')
        burpgroup.add_argument('--burp-port', type=int, default=1337, help='🔌 Burp Suite REST API port (default: 1337)')
        burpgroup.add_argument('--burp-api-key', help='🔑 Burp Suite API key (required for authenticated access)')
        burpgroup.add_argument('--burp-scan-type', choices=['passive', 'active', 'both'], default='passive', help='📊 Burp scan type (default: passive)')
        burpgroup.add_argument('--burp-crawl-strategy', choices=['most_complete', 'more_complete', 'fastest'], default='more_complete', help='🕷️ Burp crawl strategy')
        burpgroup.add_argument('--burp-max-crawl-time', type=int, default=10, help='⏱️ Max crawl time in minutes (default: 10)')
        burpgroup.add_argument('--burp-max-audit-time', type=int, default=20, help='🔍 Max audit time in minutes (default: 20)')
        burpgroup.add_argument('--burp-output-dir', default='burp_results', help='📁 Burp results output directory')

        # AI Analysis - Enhanced
        aigroup = parser.add_argument_group('🤖 AI-Powered Analysis')
        aigroup.add_argument('--grok-key', help='🧠 Grok AI API key for vulnerability analysis')

        args = parser.parse_args()

        # Handle special performance commands
        if args.performance_report:
            report = get_performance_report()
            
            # Generate and save detailed report in requested format
            report_format = getattr(args, 'performance_format', 'txt')
            report_path = performance_logger.save_performance_report(report_format, 24)
            
            if report_format == 'txt':
                # Display detailed performance summary for text format
                print(f"\n{Fore.GREEN}📊 DETAILED PERFORMANCE REPORT{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
                detailed = report.get('detailed_performance', {})
                if detailed and 'performance_metrics' in detailed:
                    metrics = detailed['performance_metrics']
                    print(f"\n{Fore.YELLOW}🎯 OPERATION PERFORMANCE (Last 24h):{Style.RESET_ALL}")
                    print(f"   Total Events: {detailed.get('total_events', 0)}")
                    print(f"   Completed Operations: {detailed.get('completed_operations', 0)}")
                    print(f"   Success Rate: {detailed.get('success_rate', 0)}%")
                    print(f"   Average Duration: {metrics.get('avg_duration_seconds', 0):.2f}s")
                    print(f"   Max Duration: {metrics.get('max_duration_seconds', 0):.2f}s")
                    print(f"   Average Memory Delta: {metrics.get('avg_memory_delta_mb', 0):.2f}MB")
                    
                    # Show by operation type
                    by_operation = detailed.get('by_operation', {})
                    if by_operation:
                        print(f"\n{Fore.YELLOW}📋 BY OPERATION TYPE:{Style.RESET_ALL}")
                        for op_type, stats in by_operation.items():
                            print(f"   {op_type.upper()}: {stats['count']} ops, "
                                  f"avg {stats['avg_duration']:.2f}s")
                
                # Show legacy metrics for compatibility
                print(f"\n{Fore.CYAN}📈 LEGACY METRICS:{Style.RESET_ALL}")
                legacy = report.get('legacy_metrics', {})
                if legacy:
                    print(json.dumps(legacy, indent=2))
            
            print(f"\n{Fore.GREEN}💾 Performance report ({report_format.upper()}) saved: {report_path}{Style.RESET_ALL}")
            return

        if args.cache_clear:
            global_cache.clear()
            print(f"{Fore.GREEN}✅ Performance cache cleared{Style.RESET_ALL}")
            return

        if args.optimize_config:
            optimal_threads = get_optimal_thread_count()
            suggestions = profiler.resource_monitor.suggest_optimization()
            
            print(f"\n{Fore.GREEN}🚀 SYSTEM OPTIMIZATION RECOMMENDATIONS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
            print(f"Optimal Thread Count: {Fore.YELLOW}{optimal_threads}{Style.RESET_ALL}")
            
            if suggestions:
                print("Recommendations:")
                for suggestion in suggestions:
                    print(f"  • {suggestion}")
            else:
                print(f"{Fore.GREEN}System is already optimized!{Style.RESET_ALL}")
            return

        # Handle evasion profile commands
        if args.list_evasion:
            list_evasion_profiles()
            return

        if args.evasion_info:
            evasion_manager = EvasionProfileManager()
            info = evasion_manager.get_profile_info(args.evasion_info)
            if info:
                print(f"\n{Fore.CYAN}🥷 EVASION PROFILE: {info['name']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
                print(f"Level: {Fore.YELLOW}{info['level'].upper()}{Style.RESET_ALL}")
                print(f"Stealth Rating: {Fore.GREEN}{info['stealth_rating']}/10{Style.RESET_ALL}")
                print(f"Speed Impact: {Fore.RED}{info['estimated_time_multiplier']:.1f}x slower{Style.RESET_ALL}")
                print(f"Description: {info['description']}")
                print(f"Target Systems: {', '.join(info['target_systems'])}")
            else:
                print(f"{Fore.RED}❌ Evasion profile '{args.evasion_info}' not found{Style.RESET_ALL}")
            return

        # Handle tool listing
        if args.list_tools:
            show_available_tools()
            return

        # Create output directory
        os.makedirs(args.outdir, exist_ok=True)

        # Prepare targets
        targets = []
        if args.iL:
            targets.extend(load_targets_from_file(args.iL))
        elif args.iR:
            targets = [f"-iR {args.iR}"]
        else:
            if not args.targets:
                print(f"{Fore.RED}Error: No targets specified. Use 'targets' positional argument, -iL, or -iR{Style.RESET_ALL}")
                parser.print_help()
                sys.exit(2)
            for t in args.targets:
                if t.startswith('@'):
                    path = t[1:]
                    if not os.path.isabs(path):
                        path = os.path.join(os.getcwd(), path)
                    if not os.path.exists(path):
                        print(f"Target file not found: {path}")
                        continue
                    targets.extend(load_targets_from_file(path))
                else:
                    targets.append(t)

        if not targets and not args.iR:
            print("No targets to scan after processing inputs.")
            sys.exit(1)

        # Setup tool chaining configuration
        tool_chain_config = None
        if args.chain_tools or args.select_tools:
            tool_chain_config = {
                'enabled': True,
                'config_path': args.tools_config or 'tools.config.example.json',
                'selected_tools': args.select_tools.split(',') if args.select_tools else None,
                'parallel': args.tools_parallel,
                'output_dir': args.tools_output
            }
            if tool_chain_config['enabled']:
                print_tool_chain_banner()
                print(f"{Fore.GREEN}🔗 Tool chaining enabled with {len(tool_chain_config['selected_tools']) if tool_chain_config['selected_tools'] else 'auto-detected'} tools{Style.RESET_ALL}")

        # Setup Burp Suite configuration
        burp_config = None
        if args.burp:
            burp_config = {
                'enabled': True,
                'host': args.burp_host,
                'port': args.burp_port,
                'api_key': args.burp_api_key,
                'scan_type': args.burp_scan_type,
                'crawl_strategy': args.burp_crawl_strategy,
                'max_crawl_time': args.burp_max_crawl_time,
                'max_audit_time': args.burp_max_audit_time,
                'output_dir': args.burp_output_dir
            }
            if burp_config['enabled']:
                if check_burp_availability():
                    print_burp_banner()
                    print(f"{Fore.RED}🔥 Burp Suite integration enabled - Professional web application scanning{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}⚠️ Burp Suite API not available - ensure Burp Suite Professional is running on {args.burp_host}:{args.burp_port}{Style.RESET_ALL}")
                    burp_config['enabled'] = False

        # Set async mode in args for worker function
        args.async_mode = getattr(args, 'async_mode', False)

        # Display performance optimization status
        if args.async_mode:
            print(f"{Fore.CYAN}⚡ Async mode enabled - Enhanced performance with concurrent scanning{Style.RESET_ALL}")
            
        optimal_threads = get_optimal_thread_count() if args.threads <= 0 else args.threads
        print(f"{Fore.CYAN}🔧 Performance optimizations active - Using {optimal_threads} threads{Style.RESET_ALL}")

        # Display evasion profile status
        if hasattr(args, 'evasion') and args.evasion:
            evasion_manager = EvasionProfileManager()
            evasion_manager.print_evasion_banner(args.evasion)
            
            # Apply target randomization if specified
            if args.randomize_order or evasion_manager.get_profile(args.evasion).randomize_hosts:
                import random
                random.shuffle(targets)
                print(f"{Fore.YELLOW}🔀 Target order randomized for evasion{Style.RESET_ALL}")

        # Run the actual scanning
        if args.schedule:
            # Parse schedule interval
            interval = args.schedule.lower()
            if interval.endswith('h'):
                schedule.every(int(interval[:-1])).hours.do(
                    run_scheduled_scan, args, targets, None, tool_chain_config, burp_config)
            elif interval.endswith('d'):
                schedule.every(int(interval[:-1])).days.do(
                    run_scheduled_scan, args, targets, None, tool_chain_config, burp_config)
            else:
                logger.error("Invalid schedule format. Use '1h' for hourly or '1d' for daily.")
                sys.exit(1)
            
            logger.info(f"Starting scheduled scans with interval: {interval}")
            run_scheduled_scan(args, targets, None, tool_chain_config, burp_config)
            
            # Run schedule loop
            try:
                import itertools
                spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'])
                while True:
                    schedule.run_pending()
                    for _ in range(60):
                        print(f"\r{Fore.CYAN}⏰ Waiting for next scan... {next(spinner)}{Style.RESET_ALL}", 
                              end='', flush=True)
                        time.sleep(1)
                    print()
            except KeyboardInterrupt:
                logger.info("Scheduled scans stopped by user")
        else:
            # Single run mode with performance optimization
            run_scheduled_scan(args, targets, None, tool_chain_config, burp_config)

    except KeyboardInterrupt:
        logger.warning("❌ Scan interrupted by user")
        
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        
    finally:
        # Final performance report with smart cache analytics
        final_metrics = profiler.end_profiling(main_metrics)
        
        # Get smart cache analytics before cleanup
        smart_cache_stats = None
        cache_optimization_result = None
        
        if smart_caching_available:
            try:
                smart_cache_stats = cache_manager.get_analytics()
                cache_optimization_result = cache_manager.optimize()
                
                # Adaptive cache resize based on performance
                resize_result = cache_manager.adaptive_resize()
                if "Increased" in resize_result or "Reduced" in resize_result:
                    logger.info(f"🔧 Cache auto-optimized: {resize_result}")
                    
            except Exception as e:
                logger.debug(f"Smart cache analytics error: {e}")
        
        # Clean up resources
        cleanup_performance_resources()
        
        print(f"\n{Fore.GREEN}📊 Execution completed in {final_metrics.duration:.2f} seconds{Style.RESET_ALL}")
        
        # Enhanced performance summary with smart caching
        perf_summary = profiler.get_performance_summary()
        if perf_summary and perf_summary.get('total_operations', 0) > 0:
            print(f"{Fore.CYAN}⚡ Performance Summary:{Style.RESET_ALL}")
            print(f"   Operations: {perf_summary.get('total_operations', 0)}")
            
            # Smart cache metrics if available
            if smart_cache_stats:
                cache_perf = smart_cache_stats['performance']
                print(f"   Cache Hit Rate: {cache_perf['hit_rate']}")
                if float(cache_perf['predictive_rate'].rstrip('%')) > 0:
                    print(f"   🧠 Smart Predictions: {cache_perf['predictive_rate']} success rate")
                if float(cache_perf['adaptive_rate'].rstrip('%')) > 0:
                    print(f"   🎯 Adaptive TTL: {cache_perf['adaptive_rate']} of hits")
                print(f"   Memory Usage: {smart_cache_stats['size_metrics']['memory_mb']}")
            else:
                # Fallback to basic cache stats
                basic_hit_rate = perf_summary.get('cache_statistics', {}).get('hit_rate', 'N/A')
                print(f"   Cache Hit Rate: {basic_hit_rate}")
                
            print(f"   Peak Memory: {perf_summary.get('peak_memory_usage_mb', 0):.1f}MB")
            
            # Show cache optimization recommendations
            if cache_optimization_result and cache_optimization_result.get('recommendations'):
                print(f"{Fore.YELLOW}💡 Cache Recommendations:{Style.RESET_ALL}")
                for rec in cache_optimization_result['recommendations'][:2]:  # Show top 2
                    print(f"   • {rec}")
        
        # Log final smart cache state
        if smart_caching_available and smart_cache_stats:
            cache_entries = smart_cache_stats['size_metrics']['entries']
            if cache_entries > 0:
                logger.info(f"🧠 Smart cache saved {cache_entries} entries for next session")


if __name__ == '__main__':
    main()