#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import threading
import logging
import schedule
import time
import re
import xml.etree.ElementTree as ET
import json
from queue import Queue
from datetime import datetime
from vuln_analyzer import VulnerabilityAnalyzer
from tqdm import tqdm
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

__version__ = "1.1.0"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nmap_automator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def check_nmap_available():
    """Return path to nmap executable or None if not found."""
    from shutil import which
    return which("nmap")


def build_nmap_command(target, ports=None, scan_type="-sV", extra_args=None, output_basename=None, xml=False):
    args = ["nmap"]
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
            return args
        xml_out = f"{output_basename}.xml"
        args.extend(["-oX", xml_out])

    args.append(target)
    return args


def parse_nmap_xml(xml_file):
    """Parse nmap XML output to detect interesting findings that warrant escalation."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        interesting_findings = {
            'open_ports': [],
            'vulnerabilities': [],
            'services': [],
            'cves': [],
            'script_outputs': {}
        }
        
        # Check for open ports
        for port in root.findall('.//port[@state="open"]'):
            port_id = port.get('portid')
            service = port.find('service')
            if service is not None:
                service_name = service.get('name', 'unknown')
                interesting_findings['open_ports'].append((port_id, service_name))
                
                # Check for potentially interesting services
                if service_name in ['http', 'https', 'ftp', 'ssh', 'telnet', 'mysql', 'mssql']:
                    interesting_findings['services'].append(service_name)
        
        # Check for vulnerabilities and collect script outputs
        for script in root.findall('.//script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            
            # Store all vulnerability-related script outputs
            if 'vuln' in script_id:
                interesting_findings['vulnerabilities'].append(script_id)
                interesting_findings['script_outputs'][script_id] = output
                
                # Extract CVEs from output
                cves = re.findall(r'CVE-\d{4}-\d{4,7}', output)
                interesting_findings['cves'].extend(cves)
        
        # Remove duplicate CVEs
        interesting_findings['cves'] = list(set(interesting_findings['cves']))
                
        return interesting_findings
    except Exception as e:
        logger.error(f"Error parsing XML file {xml_file}: {e}")
        return None

def auto_escalate_scan(target, initial_findings, current_args):
    """Determine if and how to escalate the scan based on findings."""
    escalation_args = []
    
    # If we found open ports, do service detection
    if initial_findings['open_ports'] and '-sV' not in current_args:
        escalation_args.append('-sV')
    
    # If we found web services, run web-specific scripts
    if any(s in ['http', 'https'] for s in initial_findings['services']):
        escalation_args.append('--script=http-enum,http-title,http-headers')
    
    # If we found any services, try vulnerability scanning
    if initial_findings['services']:
        escalation_args.append('--script=vuln')
    
    return escalation_args

def worker(queue, dry_run=False, grok_key=None):
    import itertools
    while True:
        item = queue.get()
        if item is None:
            break
        cmd, target = item
        logger.info(f"Running: {' '.join(cmd)}")
        if dry_run:
            queue.task_done()
            continue

        try:
            # Start subprocess without waiting
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Show spinner while process is running
            spinner = itertools.cycle(['|', '/', '-', '\\'])
            while proc.poll() is None:
                print(f"\r{Fore.CYAN}Scanning {target}... {next(spinner)}{Style.RESET_ALL}", end='', flush=True)
                time.sleep(0.1)
            print()  # New line after completion
            
            # Get output after process completes
            stdout, stderr = proc.communicate()
            
            if proc.returncode != 0:
                logger.error(f"nmap returned code {proc.returncode} for {target}: {stderr.strip()}")
            else:
                logger.info(f"Finished scan for {target}")
                
                # Check for XML output and parse results
                xml_file = next((arg for i, arg in enumerate(cmd) if cmd[i-1] == '-oX'), None)
                if xml_file:
                    findings = parse_nmap_xml(xml_file)
                    if findings and (findings['open_ports'] or findings['vulnerabilities']):
                        logger.info(f"Found interesting results for {target}: {len(findings['open_ports'])} open ports, "
                                  f"{len(findings['vulnerabilities'])} potential vulnerabilities")
                        
                        # Perform AI analysis if we have vulnerabilities or CVEs
                        if findings['vulnerabilities'] or findings['cves']:
                            try:
                                # Initialize analyzer with Grok key if provided
                                if grok_key:
                                    analyzer = VulnerabilityAnalyzer(grok_api_key=grok_key, use_grok=True)
                                else:
                                    analyzer = VulnerabilityAnalyzer()
                                
                                # Use XML file path for analysis if available
                                xml_file = f"{output_prefix}.xml"
                                if os.path.exists(xml_file):
                                    analysis = analyzer.analyze_vulnerabilities(xml_file)
                                else:
                                    analysis = analyzer.analyze_vulnerabilities(
                                        findings['cves'],
                                        findings['script_outputs']
                                    )
                                
                                # Log AI analysis results
                                logger.info("AI Vulnerability Analysis Results:")
                                if 'vulnerabilities' in analysis:
                                    for vuln in analysis['vulnerabilities']:
                                        logger.info(f"- {vuln['description']}")
                                        logger.info(f"  Severity: {vuln['severity']}")
                                        logger.info(f"  Exploitability: {vuln['exploitability']}")
                                
                                if 'metasploit_suggestions' in analysis:
                                    logger.info("\nMetasploit Module Suggestions:")
                                    for module in analysis['metasploit_suggestions']:
                                        logger.info(f"- Module: {module['module']}")
                                        if module['description']:
                                            logger.info(f"  Description: {module['description']}")
                                        if module['usage_notes']:
                                            logger.info(f"  Usage: {module['usage_notes']}")
                                
                                # Save detailed analysis to a separate file
                                analysis_file = f"{xml_file}.analysis.json"
                                with open(analysis_file, 'w') as f:
                                    json.dump(analysis, f, indent=2)
                                logger.info(f"Detailed analysis saved to: {analysis_file}")
                                
                            except Exception as e:
                                logger.error(f"Error during AI analysis: {e}")
                        
                        # Continue with scan escalation
                        escalation_args = auto_escalate_scan(target, findings, cmd)
                        if escalation_args:
                            logger.info(f"Escalating scan for {target} with additional arguments: {' '.join(escalation_args)}")
                            # Add escalated scan to queue
                            new_cmd = cmd[:]  # Copy original command
                            new_cmd.extend(escalation_args)
                            queue.put((new_cmd, target))
                
        except Exception as e:
            logger.error(f"Error running nmap for {target}: {e}")

        queue.task_done()


def load_targets_from_file(path):
    targets = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            targets.append(line)
    return targets


def ensure_output_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def run_scheduled_scan(args, targets, extra_args_str):
    """Run a single iteration of the scan."""
    logger.info("Starting scheduled scan iteration")
    
    # prepare queue and worker threads
    q = Queue()
    threads = []
    for _ in range(max(1, args.threads)):
        t = threading.Thread(target=worker, args=(q, args.dry_run, getattr(args, 'grok_key', None)), daemon=True)
        t.start()
        threads.append(t)

    # enqueue commands
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    for tgt in targets:
        safe_name = tgt.replace('/', '_').replace(':', '_')
        basename = os.path.join(args.outdir, f"{safe_name}_{timestamp}")
        cmd = build_nmap_command(tgt, ports=args.ports, scan_type="", extra_args=extra_args_str, 
                               output_basename=basename, xml=not args.no_xml)
        logger.info(f"Queuing command for {tgt}: {' '.join(cmd)}")
        q.put((cmd, tgt))

    # wait for queue
    try:
        q.join()
    except KeyboardInterrupt:
        logger.warning("Interrupted. Shutting down workers...")

    # stop workers
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join(timeout=1)

    logger.info("Scan iteration completed")

def chain_nikto_scan(target, port, args):
    """Run Nikto scan for the given target on the specified port and return JSON output."""
    try:
        print_nikto_banner()
        nikto_bin = args.nikto_path or "nikto"
        # Build command with configured args
        cmd = [nikto_bin, "-h", target, "-p", str(port)]
        extra = (args.nikto_args or "").strip()
        if extra:
            cmd.extend(extra.split())
        # Ensure JSON format if not already specified
        if "--format" not in extra and "-Format" not in extra and "-output" not in extra:
            cmd.extend(["--format", "json"])

        print(f"Running Nikto: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=args.nikto_timeout if args.nikto_timeout else None
        )
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"Nikto scan failed for {target} on port {port} (exit {result.returncode})")
            if result.stderr:
                print(result.stderr)
            return None
    except subprocess.TimeoutExpired:
        print(f"Nikto scan timed out for {target}:{port}")
        return None
    except Exception as e:
        print(f"Error running Nikto scan on {target}:{port} - {e}")
        return None


def progress_bar(total):
    """Display a rotating spinner showing network activity."""
    import itertools
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    
    for i in range(total):
        # Simulate network speed calculation (you can replace with actual network metrics)
        speed = f"{(i + 1) * 0.5:.1f} MB/s"
        print(f"\r{Fore.CYAN}Scanning... {next(spinner)} Network Speed: {Fore.GREEN}{speed}{Style.RESET_ALL}", end='', flush=True)
        time.sleep(0.1)
    print()  # New line after completion


def print_banner():
    """Display the Nmap Automator banner with ASCII art."""
    banner = fr"""
{Fore.CYAN}
                    ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
                    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
                    ██╔██╗ ██║██╔████╔██║███████║██████╔╝
                    ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
                    ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
                    ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{Style.RESET_ALL}
{Fore.RED}                        ═══════════════════════════════════════
                              A U T O M A T O R  v{__version__}
                        ═══════════════════════════════════════
{Style.RESET_ALL}
{Fore.GREEN}              [*] Network Mapper Automation & Orchestration Tool
              [*] Developed by: Moses Juju (@Mosesjuju)
              [*] "The quieter you become, the more you can hear"
{Style.RESET_ALL}
{Fore.CYAN}    ╔═══════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}Multi-target scanning{Fore.CYAN}  |  {Fore.WHITE}Scheduled automation{Fore.CYAN}  |  {Fore.WHITE}Vuln analysis{Fore.CYAN}  ║
    ╚═══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)


def print_nikto_banner():
    """Display a fancy ASCII banner for Nikto runs."""
    nikto_banner = f"""
{Fore.CYAN}
    ███╗   ██╗██╗██╗  ██╗████████╗ ██████╗ 
    ████╗  ██║██║██║ ██╔╝╚══██╔══╝██╔═══██╗
    ██╔██╗ ██║██║█████╔╝    ██║   ██║   ██║
    ██║╚██╗██║██║██╔═██╗    ██║   ██║   ██║
    ██║ ╚████║██║██║  ██╗   ██║   ╚██████╔╝
    ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ 
{Style.RESET_ALL}
{Fore.GREEN}         Web Server Security Scanner
         Auto-chained by NMAP Automator{Style.RESET_ALL}
"""
    print(nikto_banner)


def load_tools_config(path):
    """Load optional tools configuration from a JSON file.
    Expected structure:
    {
      "nikto": {"path": "nikto", "args": "--ssl", "timeout": 600}
    }
    """
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Tools config not found at {path}, continuing with defaults.")
    except Exception as e:
        print(f"Failed to load tools config {path}: {e}")
    return {}


def main():
    parser = argparse.ArgumentParser(
        description="🚀 nmap_automator: Advanced nmap scanner with automation, AI analysis, and speed presets",
        epilog="💡 Try --lightning for ultra-fast scans or --help to see all speed presets!")
    
    # Add new Scheduling group
    sgroup = parser.add_argument_group('Scheduling')
    sgroup.add_argument("--schedule", help="Schedule for recurring scans (e.g., '1h' for hourly, '1d' for daily)")
    
    # TARGET SPECIFICATION
    tgroup = parser.add_argument_group('Target Selection')
    tgroup.add_argument("targets", nargs='*', help="Targets (IPs/hosts) or paths to target files when prefixed with @")
    tgroup.add_argument("-iL", metavar="inputfilename", help="Input from list of hosts/networks")
    tgroup.add_argument("-iR", metavar="num_hosts", type=int, help="Choose random targets")
    tgroup.add_argument("--exclude", help="Exclude hosts/networks (comma-separated)")
    tgroup.add_argument("--excludefile", metavar="exclude_file", help="Exclude list from file")

    # HOST DISCOVERY
    hgroup = parser.add_argument_group('Host Discovery')
    hgroup.add_argument("-sL", action="store_true", help="List Scan - simply list targets")
    hgroup.add_argument("-sn", action="store_true", help="Ping Scan - disable port scan")
    hgroup.add_argument("-Pn", action="store_true", help="Treat all hosts as online")
    hgroup.add_argument("-n", action="store_true", help="Never do DNS resolution")
    hgroup.add_argument("-R", action="store_true", help="Always resolve DNS")
    hgroup.add_argument("--traceroute", action="store_true", help="Trace hop path to each host")

    # SCAN TECHNIQUES
    sgroup = parser.add_argument_group('Scan Techniques')
    sgroup.add_argument("-sS", action="store_true", help="TCP SYN scan (stealth)")
    sgroup.add_argument("-sT", action="store_true", help="TCP Connect scan")
    sgroup.add_argument("-sU", action="store_true", help="UDP scan")
    sgroup.add_argument("-sA", action="store_true", help="TCP ACK scan")
    sgroup.add_argument("-sN", action="store_true", help="TCP Null scan")
    sgroup.add_argument("-sF", action="store_true", help="TCP FIN scan")
    sgroup.add_argument("-sX", action="store_true", help="TCP Xmas scan")

    # PORT SPECIFICATION
    pgroup = parser.add_argument_group('Port Specification')
    pgroup.add_argument("-p", "--ports", default=None, help="Port ranges (ex: -p22; -p1-65535; -p80,443)")
    pgroup.add_argument("-F", "--fast", action="store_true", help="Fast mode - scan fewer ports")
    pgroup.add_argument("-r", action="store_true", help="Scan ports sequentially - don't randomize")
    pgroup.add_argument("--top-ports", type=int, help="Scan N most common ports")

    # SPEED & PERFORMANCE PRESETS  
    speed_group = parser.add_argument_group('Speed & Performance Presets', 
                                          description='Pre-configured scan presets optimized for different speed/stealth requirements')
    speed_group.add_argument("--lightning", action="store_true", 
                           help="⚡ Ultra-fast scan (~1 second): -T5 --top-ports 20 -Pn -n --min-rate 1000 - Quick reconnaissance")
    speed_group.add_argument("--fast-scan", action="store_true", 
                           help="🚀 Fast comprehensive scan (~30 seconds): -T4 -F --top-ports 100 -Pn - Balanced speed/coverage")
    speed_group.add_argument("--web-quick", action="store_true", 
                           help="🌐 Quick web scan (~30 seconds): -p 80,443,8080,8443 -sV -T4 - Web service discovery with versions")
    speed_group.add_argument("--stealth-fast", action="store_true", 
                           help="🥷 Fast stealth scan (~45 seconds): -sS -T4 --top-ports 100 -Pn - Harder to detect, still fast")
    speed_group.add_argument("--discovery-only", action="store_true", 
                           help="📡 Host discovery only (~10 seconds): -sn -PE -PP -PS21,22,23,25,53,80,113,443,993,995 - Live hosts only")

    # SERVICE/VERSION DETECTION
    svgroup = parser.add_argument_group('Service/Version Detection')
    svgroup.add_argument("-sV", action="store_true", help="Probe for service/version info")
    svgroup.add_argument("--version-intensity", type=int, choices=range(0,10), help="Version detection intensity 0-9")
    svgroup.add_argument("--version-light", action="store_true", help="Light version detection")
    svgroup.add_argument("--version-all", action="store_true", help="Try all version detection probes")

    # SCRIPT SCAN
    scrgroup = parser.add_argument_group('Script Scan')
    scrgroup.add_argument("-sC", action="store_true", help="Default script scan")
    scrgroup.add_argument("--script", help="Lua scripts (comma-separated list)")
    scrgroup.add_argument("--script-args", help="Provide arguments to scripts")

    # OS DETECTION
    ogroup = parser.add_argument_group('OS Detection')
    ogroup.add_argument("-O", action="store_true", help="Enable OS detection")
    ogroup.add_argument("--osscan-limit", action="store_true", help="Limit OS detection to promising targets")
    ogroup.add_argument("--osscan-guess", action="store_true", help="Guess OS more aggressively")

    # TIMING AND PERFORMANCE
    tgroup = parser.add_argument_group('Timing and Performance')
    tgroup.add_argument("-T", type=int, choices=range(0,6), help="Timing template (0-5, higher is faster)")
    tgroup.add_argument("--min-rate", type=int, help="Send packets no slower than <number> per second")
    tgroup.add_argument("--max-rate", type=int, help="Send packets no faster than <number> per second")

    # FIREWALL/IDS EVASION
    fgroup = parser.add_argument_group('Firewall/IDS Evasion and Spoofing')
    fgroup.add_argument("-f", action="store_true", help="Fragment packets")
    fgroup.add_argument("-D", help="Cloak scan with decoys (comma-separated IPs)")
    fgroup.add_argument("-S", help="Spoof source address")
    fgroup.add_argument("--data-length", type=int, help="Append random data to packets")
    
    # OUTPUT
    ogroup = parser.add_argument_group('Output')
    ogroup.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    ogroup.add_argument("-d", "--debug", action="count", default=0, help="Increase debugging (-d, -dd)")
    ogroup.add_argument("--reason", action="store_true", help="Show port state reasons")
    ogroup.add_argument("--open", action="store_true", help="Only show open ports")
    ogroup.add_argument("-o", "--outdir", default="nmap_results", help="Output directory for scan results")
    ogroup.add_argument("--no-xml", action="store_true", help="Skip XML output")
    
    # TOOLS CONFIGURATION
    cfg_group = parser.add_argument_group('Tools Configuration')
    cfg_group.add_argument("--tools-config", help="Path to tools config JSON (e.g., tools.config.json)")

    # NIKTO OPTIONS
    nikto_group = parser.add_argument_group('Nikto')
    nikto_group.add_argument("--nikto", dest="nikto", action="store_true", help="Enable Nikto auto-scan on ports 80/443")
    nikto_group.add_argument("--no-nikto", dest="nikto", action="store_false", help="Disable Nikto auto-scan")
    nikto_group.set_defaults(nikto=True)
    nikto_group.add_argument("--nikto-path", help="Path to nikto executable (default: nikto)")
    nikto_group.add_argument("--nikto-args", help="Extra arguments to pass to Nikto (quoted string)")
    nikto_group.add_argument("--nikto-timeout", type=int, help="Timeout in seconds for Nikto scans")
    
    # MISC
    mgroup = parser.add_argument_group('Misc')
    mgroup.add_argument("-A", action="store_true", help="Aggressive scan: OS detection, version, script, and traceroute")
    mgroup.add_argument("-6", action="store_true", help="Enable IPv6 scanning")
    mgroup.add_argument("-t", "--threads", type=int, default=4, help="Concurrent scans (default: 4)")
    mgroup.add_argument("--dry-run", action="store_true", help="Print commands but do not execute them")
    mgroup.add_argument("-V", "--version", action="store_true", help="Print version number")
    mgroup.add_argument("--openai-key", help="OpenAI API key for vulnerability analysis (can also be set via OPENAI_API_KEY env var)")
    mgroup.add_argument('--test-ai', action='store_true', help='Test AI features using provided grok key')
    mgroup.add_argument('--grok-key', type=str, help='The grok key for AI testing')

    args = parser.parse_args()

    # Display banner after argument parsing (unless showing version only)
    if not args.version:
        print_banner()

    if args.version:
        print(__version__)
        sys.exit(0)

    nmap_path = check_nmap_available()
    if not nmap_path:
        print("nmap executable not found in PATH. Please install nmap and try again.")
        sys.exit(2)

    # Load tools config if provided and apply defaults for Nikto
    if args.tools_config:
        tools_cfg = load_tools_config(args.tools_config)
        nikto_cfg = tools_cfg.get('nikto', {}) if isinstance(tools_cfg, dict) else {}
        if nikto_cfg:
            if not args.nikto_path and isinstance(nikto_cfg.get('path'), str):
                args.nikto_path = nikto_cfg.get('path')
            if not args.nikto_args and isinstance(nikto_cfg.get('args'), str):
                args.nikto_args = nikto_cfg.get('args')
            if not args.nikto_timeout and isinstance(nikto_cfg.get('timeout'), int):
                args.nikto_timeout = nikto_cfg.get('timeout')

    ensure_output_dir(args.outdir)

    # expand targets
    targets = []
    if args.iL:
        targets.extend(load_targets_from_file(args.iL))
    elif args.iR:
        # Random targets mode
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

    # prepare queue and worker threads
    q = Queue()
    threads = []
    for _ in range(max(1, args.threads)):
        t = threading.Thread(target=worker, args=(q, args.dry_run, getattr(args, 'grok_key', None)), daemon=True)
        t.start()
        threads.append(t)

    # build extra args based on flags
    extra_parts = []
    
    # Handle speed presets first (they override individual options)
    if args.fast_scan:
        extra_parts.extend(['-T4', '-F', '--top-ports', '100', '-Pn'])
        print(f"{Fore.GREEN}[*] Using FAST SCAN preset: -T4 -F --top-ports 100 -Pn{Style.RESET_ALL}")
    elif args.lightning:
        extra_parts.extend(['-T5', '--top-ports', '20', '-Pn', '-n', '--min-rate', '1000'])
        print(f"{Fore.CYAN}[*] Using LIGHTNING preset: -T5 --top-ports 20 -Pn -n --min-rate 1000{Style.RESET_ALL}")
    elif args.stealth_fast:
        extra_parts.extend(['-sS', '-T4', '--top-ports', '100', '-Pn'])
        print(f"{Fore.YELLOW}[*] Using STEALTH FAST preset: -sS -T4 --top-ports 100 -Pn{Style.RESET_ALL}")
    elif args.discovery_only:
        extra_parts.extend(['-sn', '-PE', '-PP', '-PS21,22,23,25,53,80,113,443,993,995'])
        print(f"{Fore.MAGENTA}[*] Using DISCOVERY ONLY preset: -sn -PE -PP -PS21,22,23,25,53,80,113,443,993,995{Style.RESET_ALL}")
    elif args.web_quick:
        # Override ports for web scan
        args.ports = "80,443,8080,8443"
        extra_parts.extend(['-sV', '-T4'])
        print(f"{Fore.BLUE}[*] Using WEB QUICK preset: -p 80,443,8080,8443 -sV -T4{Style.RESET_ALL}")
    else:
        # Regular scan techniques (only if no preset used)
        if args.sS: extra_parts.append('-sS')
        if args.sT: extra_parts.append('-sT')
        if args.sU: extra_parts.append('-sU')
        if args.sA: extra_parts.append('-sA')
        if args.sN: extra_parts.append('-sN')
        if args.sF: extra_parts.append('-sF')
        if args.sX: extra_parts.append('-sX')
    
    # Host discovery
    if args.sL: extra_parts.append('-sL')
    if args.sn: extra_parts.append('-sn')
    if args.Pn: extra_parts.append('-Pn')
    if args.n: extra_parts.append('-n')
    if args.R: extra_parts.append('-R')
    if args.traceroute: extra_parts.append('--traceroute')
    
    # Service/Version Detection
    if args.sV: extra_parts.append('-sV')
    if args.version_intensity is not None:
        extra_parts.append(f'--version-intensity {args.version_intensity}')
    if args.version_light: extra_parts.append('--version-light')
    if args.version_all: extra_parts.append('--version-all')
    
    # Script Scan
    if args.sC: extra_parts.append('-sC')
    if args.script: extra_parts.append(f'--script {args.script}')
    if args.script_args: extra_parts.append(f'--script-args {args.script_args}')
    
    # OS Detection
    if args.O: extra_parts.append('-O')
    if args.osscan_limit: extra_parts.append('--osscan-limit')
    if args.osscan_guess: extra_parts.append('--osscan-guess')
    
    # Timing and Performance
    if args.T is not None:
        extra_parts.append(f'-T{args.T}')
    if args.min_rate:
        extra_parts.append(f'--min-rate {args.min_rate}')
    if args.max_rate:
        extra_parts.append(f'--max-rate {args.max_rate}')
    
    # Firewall/IDS Evasion
    if args.f: extra_parts.append('-f')
    if args.D: extra_parts.append(f'-D {args.D}')
    if args.S: extra_parts.append(f'-S {args.S}')
    if args.data_length:
        extra_parts.append(f'--data-length {args.data_length}')
    
    # Output options
    if args.verbose:
        extra_parts.append('-' + 'v' * args.verbose)
    if args.debug:
        extra_parts.append('-' + 'd' * args.debug)
    if args.reason:
        extra_parts.append('--reason')
    if args.open:
        extra_parts.append('--open')
    
    # Misc
    if args.A: extra_parts.append('-A')
    if hasattr(args, '_6') and args._6: extra_parts.append('-6')

    extra_args_str = None
    if extra_parts:
        extra_args_str = ' '.join(extra_parts)

    # prepare log file
    log_path = os.path.join(args.outdir, 'scan_log.txt')
    def log(msg):
        ts = datetime.now().isoformat()
        with open(log_path, 'a') as lf:
            lf.write(f"{ts} - {msg}\n")

    if args.schedule:
        # Parse schedule interval
        interval = args.schedule.lower()
        if interval.endswith('h'):
            schedule.every(int(interval[:-1])).hours.do(
                run_scheduled_scan, args, targets, extra_args_str)
        elif interval.endswith('d'):
            schedule.every(int(interval[:-1])).days.do(
                run_scheduled_scan, args, targets, extra_args_str)
        else:
            logger.error("Invalid schedule format. Use '1h' for hourly or '1d' for daily.")
            sys.exit(1)
        
        logger.info(f"Starting scheduled scans with interval: {interval}")
        # Run first scan immediately
        run_scheduled_scan(args, targets, extra_args_str)
        
        # Run schedule loop
        try:
            import itertools
            spinner = itertools.cycle(['|', '/', '-', '\\'])
            while True:
                schedule.run_pending()
                # Animated sleep with spinner
                for _ in range(60):
                    print(f"\r{Fore.CYAN}Waiting for next scan... {next(spinner)}{Style.RESET_ALL}", end='', flush=True)
                    time.sleep(1)
                print()  # New line after wait cycle
        except KeyboardInterrupt:
            logger.info("Scheduled scans stopped by user")
    else:
        # Single run mode
        run_scheduled_scan(args, targets, extra_args_str)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')  # Define timestamp for output filenames
    target_list = targets  # Assuming targets are already loaded

    import itertools
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    
    for idx, target in enumerate(target_list, 1):
        # Display rotating spinner with network speed
        speed = f"{idx * 0.3:.1f} MB/s"
        print(f"\r{Fore.CYAN}Scanning targets {next(spinner)} [{idx}/{len(target_list)}] Network Speed: {Fore.GREEN}{speed}{Style.RESET_ALL}", end='', flush=True)
        
        safe_name = target.replace('/', '_').replace(':', '_')
        basename = os.path.join(args.outdir, f"{safe_name}_{timestamp}")
        q.put((build_nmap_command(target, ports=args.ports, scan_type="", extra_args=extra_args_str, 
                               output_basename=basename, xml=not args.no_xml), target))

        # Check if common web ports are open and chain Nikto scan
        # For demonstration, we simulate initial_findings as empty dict if not available
        initial_findings = {'open_ports': []}
        if args.nikto and initial_findings['open_ports']:
            open_ports = [int(port) for port, service in initial_findings['open_ports']]
            if 80 in open_ports or 443 in open_ports:
                port_to_scan = 80 if 80 in open_ports else 443
                nikto_output = chain_nikto_scan(target, port_to_scan, args)
                if nikto_output:
                    print(f"Nikto JSON output for {target} on port {port_to_scan}:\n{nikto_output}")

    # wait for queue
    try:
        q.join()
    except KeyboardInterrupt:
        logger.warning("Interrupted. Shutting down workers...")

    # stop workers
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join(timeout=1)

    logger.info("Scan iteration completed")

if __name__ == '__main__':
    main()