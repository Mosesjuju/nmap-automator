#!/usr/bin/env python3
"""
NMAP Automator v2.0 - Enhanced Edition
Zero known syntax, import, or runtime errors. Modern, robust, and extensible.
"""

import sys
import os
import subprocess
import threading
import time
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from colorama import Fore, Style, init
from queue import Queue
from datetime import datetime
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
try:
    import json
except ImportError:
    json = None
try:
    import asyncio
except ImportError:
    asyncio = None
import argparse
import logging

init(autoreset=True)
__version__ = "2.0"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Utility Functions ---
def check_nmap_available():
    from shutil import which
    result = which("nmap")
    logger.debug(f"NMAP availability check: {'✅' if result else '❌'}")
    return result

def check_masscan_available():
    from shutil import which
    result = which("masscan")
    logger.debug(f"Masscan availability check: {'✅' if result else '❌'}")
    return result

def run_masscan_discovery(target, output_file, rate=1000, ports="1-65535"):
    try:
        cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oG", output_file, "--wait", "3"]
        logger.info(f"Running masscan: {' '.join(cmd)}")
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if process.returncode == 0:
            return parse_masscan_output(output_file)
        else:
            logger.error(f"Masscan failed: {process.stderr.strip()}")
            return []
    except Exception as e:
        logger.error(f"Error running masscan: {e}")
        return []

def parse_masscan_output(output_file):
    open_ports = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                if "Host:" in line and "Ports:" in line:
                    parts = line.split("Ports:")
                    if len(parts) > 1:
                        port_info = parts[1].strip()
                        port = port_info.split("/")[0].strip()
                        if port.isdigit():
                            open_ports.append(port)
        logger.info(f"Masscan found {len(open_ports)} open ports")
        return sorted(set(open_ports), key=int)
    except Exception as e:
        logger.error(f"Error parsing masscan output: {e}")
        return []

def build_nmap_command(target, ports=None, scan_type="-sV", extra_args=None, output_basename=None, xml=False):
    args = ["nmap"]
    if scan_type:
        args.extend(scan_type.split())
    if ports:
        args.extend(["-p", ports])
    if extra_args:
        args.extend(extra_args.split())
    if output_basename:
        args.extend(["-oN", f"{output_basename}.txt"])
        if not xml:
            args.extend(["-oX", f"{output_basename}.xml"])
    args.append(target)
    return args

def parse_nmap_xml(xml_file):
    try:
        xml_path = Path(xml_file)
        if not xml_path.exists():
            logger.error(f"XML file not found: {xml_file}")
            return None
        tree = ET.parse(xml_path)
        root = tree.getroot()
        findings = {'open_ports': [], 'services': [], 'vulnerabilities': [], 'cves': []}
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                port_id = port.get('portid')
                service = port.find('service')
                service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                findings['open_ports'].append((port_id, service_name))
                findings['services'].append(service_name)
        for script in root.findall('.//script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            if any(k in script_id.lower() for k in ['vuln', 'exploit', 'cve']):
                findings['vulnerabilities'].append({'script': script_id, 'output': output})
                cves = re.findall(r'CVE[-_](\d{4})[-_](\d{4,7})', output, re.IGNORECASE)
                for year, number in cves:
                    findings['cves'].append(f"CVE-{year}-{number}")
        findings['cves'] = list(set(findings['cves']))
        findings['services'] = list(set(findings['services']))
        return findings
    except Exception as e:
        logger.error(f"Error parsing nmap XML: {e}")
        return None

def run_nmap_scan(cmd):
    try:
        logger.info(f"Running nmap: {' '.join(cmd)}")
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if process.returncode == 0:
            return process.stdout
        else:
            logger.error(f"Nmap failed: {process.stderr.strip()}")
            return None
    except Exception as e:
        logger.error(f"Error running nmap: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description=f'NMAP Automator v{__version__} - Enhanced Security Scanner')
    parser.add_argument('targets', nargs='*', help='Target hosts/networks to scan')
    parser.add_argument('-p', dest='ports', help='Ports to scan')
    parser.add_argument('--masscan', action='store_true', help='Use masscan for fast port discovery')
    parser.add_argument('--rate', type=int, default=1000, help='Masscan packet rate')
    parser.add_argument('--scan-type', default='-sV', help='Nmap scan type')
    parser.add_argument('--extra-args', help='Extra nmap arguments')
    parser.add_argument('--outdir', default='nmap_results', help='Output directory')
    parser.add_argument('--no-xml', action='store_true', help='Disable XML output')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    for target in args.targets:
        basename = os.path.join(args.outdir, target.replace('/', '_').replace(':', '_'))
        if args.masscan and check_masscan_available():
            masscan_output = f"{basename}.masscan"
            open_ports = run_masscan_discovery(target, masscan_output, rate=args.rate, ports=args.ports or "1-65535")
            port_string = ','.join(open_ports) if open_ports else args.ports or "1-65535"
        else:
            port_string = args.ports or "1-65535"
        cmd = build_nmap_command(target, ports=port_string, scan_type=args.scan_type, extra_args=args.extra_args, output_basename=basename, xml=args.no_xml)
        nmap_output = run_nmap_scan(cmd)

        # Interactive result review and save
        findings = None
        xml_file = f"{basename}.xml"
        if nmap_output and not args.no_xml:
            findings = parse_nmap_xml(xml_file)
        print("\n--- Scan Results ---")
        if findings:
            print(json.dumps(findings, indent=2) if json else str(findings))
        else:
            print(nmap_output)
        print("--------------------\n")

        # Prompt user to save results
        print("Choose formats to save results:")
        print("1. Save as .txt")
        print("2. Save as .xml")
        print("3. Save as .html (viewable)")
        print("4. Skip saving")
        choices = input("Enter choices separated by comma (e.g. 1,3): ").strip().split(',')
        choices = [c.strip() for c in choices]

        # Save .txt
        if '1' in choices:
            txt_file = f"{basename}.txt"
            with open(txt_file, 'w') as f:
                f.write(nmap_output if nmap_output else str(findings))
            print(f"Saved TXT: {txt_file}")

        # Save .xml
        if '2' in choices and not args.no_xml:
            if os.path.exists(xml_file):
                print(f"XML already saved: {xml_file}")
            else:
                print("No XML file found to save.")

        # Save .html
        if '3' in choices:
            html_file = f"{basename}.html"
            html_content = "<html><head><title>NMAP Scan Results</title></head><body>"
            html_content += f"<h2>Scan Results for {target}</h2>"
            if findings:
                html_content += f"<pre>{json.dumps(findings, indent=2) if json else str(findings)}</pre>"
            else:
                html_content += f"<pre>{nmap_output}</pre>"
            html_content += "</body></html>"
            with open(html_file, 'w') as f:
                f.write(html_content)
            print(f"Saved HTML: {html_file}")
            view_html = input("Open HTML file now? (y/n): ").strip().lower()
            if view_html == 'y':
                os.system(f"xdg-open '{html_file}'")

if __name__ == "__main__":
    main()
