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

WebMap can generate PDF reports from your imported Nmap XML results. You can export PDFs manually from the UI or automate conversion and artifact publishing using the included helper script and CI workflow.

Manual UI export
1) Log in to http://localhost:8000 using the token from the container:
```bash
docker exec -ti container_name /root/token
```
2) Open the host/report in the WebMap UI and use the Export/PDF button on the report toolbar (UI location varies by version).

Automated export (recommended for pipelines)

1) Helper script
- `scripts/convert_reports.sh` — finds the most recent HTML report under `nmap_results` and converts it to PDF.
- Usage (defaults to `./nmap_results` and writes PDFs to `./nmap_results/reports`):
```bash
./scripts/convert_reports.sh
# or specify input/output directories:
./scripts/convert_reports.sh /path/to/nmap_results /path/to/output_reports
```
- Behavior:
  - Prefers `wkhtmltopdf` if available on the host
  - If not available, attempts a Dockerized Chromium conversion (no host install required)
  - Prints the saved PDF path on success

2) GitHub Actions workflow
- A workflow `.github/workflows/generate-pdf.yml` will run on pushes touching `nmap_results/**` and on released publishes. It executes `scripts/convert_reports.sh` and uploads PDFs in `nmap_results/reports` as workflow artifacts.

Tips & troubleshooting
- If `wkhtmltopdf` is missing, the workflow attempts to install it; you can also install Chromium in the workflow for more accurate rendering.
- Generated PDFs are saved in your mounted `nmap_results/reports` directory (host path: `./nmap_results/reports`).
- If PDFs aren't generated, check the workflow logs in GitHub Actions and ensure HTML reports exist under `nmap_results`.



# Extending

If you want additional features such as scheduled scans or a safer interactive authorization prompt, I can add them.
