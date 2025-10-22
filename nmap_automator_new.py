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
from queue import Queue
from datetime import datetime
from vuln_analyzer import VulnerabilityAnalyzer
from tqdm import tqdm

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

def worker(queue, dry_run=False):
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
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode != 0:
                logger.error(f"nmap returned code {proc.returncode} for {target}: {proc.stderr.strip()}")
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
                                analyzer = VulnerabilityAnalyzer()
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
        t = threading.Thread(target=worker, args=(q, args.dry_run), daemon=True)
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

def chain_nikto_scan(target, port):
    """Run Nikto scan for the given target on the specified port (80 or 443) and return JSON output."""
    try:
        print(f"Running Nikto scan on {target}:{port}")
        result = subprocess.run(["nikto", "-h", target, "--format", "json"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            print(f"Nikto scan failed for {target} on port {port}")
            return None
    except Exception as e:
        print(f"Error running Nikto scan on {target}:{port} - {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="nmap_automator: run multiple nmap scans with basic orchestration")
    
    # Add new Scheduling group
    sgroup = parser.add_argument_group('Scheduling')
    sgroup.add_argument("--schedule", help="Schedule for recurring scans (e.g., '1h' for hourly, '1d' for daily)")
    
    # TARGET SPECIFICATION
    tgroup = parser.add_argument_group('Target Selection')
    tgroup.add_argument("targets", nargs='+', help="Targets (IPs/hosts) or paths to target files when prefixed with @")
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
    
    # MISC
    mgroup = parser.add_argument_group('Misc')
    mgroup.add_argument("-A", action="store_true", help="Aggressive scan: OS detection, version, script, and traceroute")
    mgroup.add_argument("-6", action="store_true", help="Enable IPv6 scanning")
    mgroup.add_argument("-t", "--threads", type=int, default=4, help="Concurrent scans (default: 4)")
    mgroup.add_argument("--dry-run", action="store_true", help="Print commands but do not execute them")
    mgroup.add_argument("-V", "--version", action="store_true", help="Print version number")
    mgroup.add_argument("--openai-key", help="OpenAI API key for vulnerability analysis (can also be set via OPENAI_API_KEY env var)")

    args = parser.parse_args()

    if args.version:
        print(__version__)
        sys.exit(0)

    nmap_path = check_nmap_available()
    if not nmap_path:
        print("nmap executable not found in PATH. Please install nmap and try again.")
        sys.exit(2)

    ensure_output_dir(args.outdir)

    # expand targets
    targets = []
    if args.iL:
        targets.extend(load_targets_from_file(args.iL))
    elif args.iR:
        # Random targets mode
        targets = [f"-iR {args.iR}"]
    else:
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
        t = threading.Thread(target=worker, args=(q, args.dry_run), daemon=True)
        t.start()
        threads.append(t)

    # build extra args based on flags
    extra_parts = []
    
    # Scan techniques
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
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("Scheduled scans stopped by user")
    else:
        # Single run mode
        run_scheduled_scan(args, targets, extra_args_str)

    target_list = targets  # Assuming targets are already loaded

    for target in tqdm(target_list, desc="Scanning targets"):
        # Existing scanning logic for each target
        safe_name = target.replace('/', '_').replace(':', '_')
        basename = os.path.join(args.outdir, f"{safe_name}_{timestamp}")
        cmd = build_nmap_command(target, ports=args.ports, scan_type="", extra_args=extra_args_str, 
                               output_basename=basename, xml=not args.no_xml)
        q.put((cmd, target))

        # Check if common web ports are open and chain Nikto scan
        open_ports = [int(port) for port, service in initial_findings['open_ports']]  # Extract port numbers
        if 80 in open_ports or 443 in open_ports:
            port_to_scan = 80 if 80 in open_ports else 443
            nikto_output = chain_nikto_scan(target, port_to_scan)
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