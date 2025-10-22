# nmap_automator 🎯

A feature-rich Python3 CLI wrapper for nmap that supports all major nmap functionality with proper argument grouping and multiple target support.

## ✨ Features
### 🎯 Target Specification
- Direct IP/hostname targets or load from files with @ prefix
- Support for `-iL` (input list) and `-iR` (random targets)
- Target exclusion with `--exclude` and `--excludefile`

### 🔍 Scan Techniques
- All major scan types:
  - `-sS`: TCP SYN scan (stealth)
  - `-sT`: TCP Connect scan
  - `-sU`: UDP scan
  - `-sA`: TCP ACK scan
  - `-sN`: TCP Null scan
  - `-sF`: TCP FIN scan
  - `-sX`: TCP Xmas scan

### 🌐 Host Discovery
- `-sL`: List scan
- `-sn`: Ping scan
- `-Pn`: Skip host discovery
- `-n/-R`: DNS resolution control
- `--traceroute`: Path tracing

### 🔌 Port Specification
- `-p`: Port ranges (e.g., -p22; -p1-65535; -p80,443)
- `-F`: Fast mode (fewer ports)
- `-r`: Sequential port scanning
- `--top-ports N`: Most common ports

### 🔧 Service/Script Features
- `-sV`: Version detection
- `-sC`: Default script scan
- `--script`: Custom script selection
- `--version-intensity`: Control version detection depth

### ⚡ Performance & Evasion
- `-T<0-5>`: Timing templates
- `--min-rate/--max-rate`: Packet rate control
- `-f`: Packet fragmentation
- `-D`: Decoy scanning
- `-S`: Source address spoofing

### 📊 Output Options
- Organized output directory with timestamped files
- Both normal (-oN) and XML (-oX) output formats
- Logging of commands and execution status
- `-v/-vv`: Verbosity control
- `--reason`: Port state reasons
- `--open`: Show only open ports

### 🤖 AI-Powered Analysis
- OpenAI integration for vulnerability assessment
- Automated CVE analysis and risk scoring
- Intelligent escalation recommendations
- `--openai-key`: Set OpenAI API key (or use OPENAI_API_KEY env var)
- Smart detection of critical vulnerabilities
- Metasploit integration suggestions

## 📚 Usage Examples

Basic stealth scan with version detection:
```bash
python3 nmap_automator.py example.com -sS -sV -p 80,443
```

Comprehensive scan with scripts and OS detection:
```bash
python3 nmap_automator.py example.com -A -sC --script vuln -v
```

Fast scan of multiple targets from a file:
```bash
python3 nmap_automator.py @targets.txt -F -T4 --top-ports 100
```

Stealth scan with evasion techniques:
```bash
python3 nmap_automator.py target.com -sS -f -D decoy1,decoy2 --data-length 24
```

Preview commands without running (dry-run):
```bash
python3 nmap_automator.py example.com -sS -A -p- --script vuln --dry-run
```

Vulnerability analysis with AI assistance:
```bash
export OPENAI_API_KEY='your-api-key'
python3 nmap_automator.py target.com -sV --script vuln -A --openai-key "$OPENAI_API_KEY"
```

## ⚠️ Safety and legality

Only scan hosts you own or have explicit permission to test. Unauthorized scanning may violate laws or acceptable-use policies. Use `--dry-run` to preview commands.

## 🔧 Extending this tool

# 🌐 WebMap Integration

This tool generates XML output by default for easy integration with WebMap. To use with WebMap:

1. Install WebMap:
```bash
docker pull reborntc/webmap
```

2. Run WebMap container:
```bash
docker run -d -p 8000:8000 -v /path/to/your/nmap_results:/opt/xml reborntc/webmap
```

3. Get WebMap login token:
```bash
# Replace container_name with your WebMap container name (e.g., jolly_hoover)
docker exec -ti container_name /root/token
```

4. Run scans with nmap_automator (XML is enabled by default):
```bash
python3 nmap_automator.py example.com -o /path/to/your/nmap_results
```

5. Access WebMap interface:
   - Open http://localhost:8000 in your browser
   - Enter the token from step 3
   - View and analyze your scan results

💡 Tips:
- Find your container name using `docker ps | grep webmap`
- If you don't need XML output, use `--no-xml` flag
- Container name changes on each run unless specified with `--name`

# 📄 Exporting PDF reports from WebMap

WebMap can generate PDF reports from your imported Nmap XML results. There are two common ways to export PDFs:

1) From the Web UI (recommended)
  - Log in to the WebMap web UI at http://localhost:8000 using your token
  - Open the host or report view you want to export
  - Click the "Export" or "PDF" button on the report toolbar (location depends on WebMap version)
  - The UI will generate and download a PDF of the current report

2) From inside the container (headless / automated)
  - WebMap stores generated HTML reports under `/opt/xml` (same path as mounted results). If you need to convert HTML to PDF yourself, use a headless browser or wkhtmltopdf.

  Example: using Chromium headless (recommended for modern HTML/CSS support):

```bash
# run inside the host (adjust paths as needed)
docker exec -ti container_name bash -c "apt-get update && apt-get install -y chromium" \
  && docker exec -ti container_name chromium --headless --disable-gpu --print-to-pdf=/opt/xml/reports/scan_report.pdf /opt/xml/reports/scan_report.html
```

  Example: using wkhtmltopdf (if available):

```bash
docker exec -ti container_name wkhtmltopdf /opt/xml/reports/scan_report.html /opt/xml/reports/scan_report.pdf
```

  Notes and tips:
  - Generated PDFs will be saved under the mounted `nmap_results` directory on the host (e.g., `/home/kali/NMAP/nmap_results/reports`).
  - If the container does not include `chromium` or `wkhtmltopdf`, you can install them inside the container or run the conversion on the host by copying the HTML files out of the container.
  - For automation, add a small script that finds the latest report HTML and converts it to PDF.


# Extending

If you want additional features such as scheduled scans or a safer interactive authorization prompt, I can add them.
