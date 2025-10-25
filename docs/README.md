# NMAP Automator v2.0 - Enhanced Edition

A modern, robust, and extensible Python tool for automated network scanning using Nmap and Masscan.
## Features
- Fast and flexible scanning with Nmap and Masscan
- XML parsing and result extraction
- Robust error handling and logging
## Usage

### Basic Scan
```
python core/nmap_automator_optimized.py scanme.nmap.org
```
### Scan Specific Ports
```
python core/nmap_automator_optimized.py scanme.nmap.org -p 1-1000
```
### Fast Scan (Top 100 ports)
```
python core/nmap_automator_optimized.py scanme.nmap.org --scan-type "-F"
```
### Use Masscan for Discovery
```
python core/nmap_automator_optimized.py scanme.nmap.org --masscan
```
### Save Results to Custom Directory
```
python core/nmap_automator_optimized.py scanme.nmap.org --outdir results
```
### Disable XML Output
```
python core/nmap_automator_optimized.py scanme.nmap.org --no-xml
```
### Save and View Results as HTML
After scanning, you will be prompted to save results as `.txt`, `.xml`, or `.html`. If you choose `.html`, you can view the file with:
```
xdg-open results/<target>.html
```
## Arguments
- `targets` (positional): Target hosts/networks to scan
- `-p PORTS`: Ports to scan (e.g., 22, 80, 443 or 1-1000)
- `--masscan`: Use masscan for fast port discovery
- `--rate RATE`: Masscan packet rate (default: 1000)
- `--scan-type SCAN_TYPE`: Nmap scan type (default: -sV)
- `--extra-args EXTRA_ARGS`: Extra nmap arguments
- `--outdir OUTDIR`: Output directory (default: nmap_results)
- `--no-xml`: Disable XML output

## Example Output
- Results are saved in the specified output directory as `.txt`, `.xml`, and `.html` files (if chosen).
- Findings are logged to the console and include open ports, services, vulnerabilities, and CVEs (if detected).

## Requirements
- Python 3.7+
- Nmap
- (Optional) Masscan
- (Optional) tqdm, colorama

## License
MIT
# �️ SecureScout v1.3.0 - Professional Cloud Security Platform

```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗      ███████╗██║     ██║   ██║██║   ██║   ██║   
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝      ╚════██║██║     ██║   ██║██║   ██║   ██║   
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   

        ═══════════════════════════════════════════════
              PROFESSIONAL CLOUD SECURITY v1.3.0  
        ═══════════════════════════════════════════════

  [*] Multi-Cloud Security Assessment Platform
  [*] "Intelligence-driven security for the modern enterprise"
```

**Professional cloud security platform with multi-cloud discovery, AI-powered risk analysis, and enterprise-grade security intelligence.**

## 🌟 Key Features

### ⚡ **Speed Presets - NEW!**
Revolutionary performance optimization with 96.4% speed improvement:

- **⚡ Lightning (`--lightning`)** - Ultra-fast scan in ~1 second
- **🚀 Fast Scan (`--fast-scan`)** - Comprehensive scan in ~30 seconds  
- **🌐 Web Quick (`--web-quick`)** - Web services discovery in ~30 seconds
- **🥷 Stealth Fast (`--stealth-fast`)** - Fast but harder to detect in ~45 seconds
- **📡 Discovery Only (`--discovery-only`)** - Live host detection in ~10 seconds

### 🤖 **AI-Powered Analysis - NEW!**
- **Grok AI Integration** - Advanced vulnerability analysis with xAI's Grok
- **OpenAI Support** - GPT-powered security insights
- **CVE Detection** - Automatic vulnerability identification from scan results
- **Metasploit Suggestions** - AI-recommended exploitation frameworks

### 🔗 **Tool Chaining - NEW!**
- **15 Security Tools** - nikto, gobuster, sslscan, enum4linux, hydra, and more
- **Configurable Parameters** - JSON-based tool configuration
- **Sequential Execution** - Smart chaining based on discovered services

### 🔥 **Burp Suite Integration - NEW!**
- **Professional Web App Testing** - REST API integration with Burp Suite Professional
- **Automated Vulnerability Scanning** - Active, passive, and crawl-only modes
- **Background Processing** - Non-blocking scan execution with progress monitoring
- **Comprehensive Reporting** - HTML/JSON/XML reports with vulnerability details

### 📅 **Automation & Scheduling**
- **Cron-like Scheduling** - Automated recurring scans (hourly, daily, weekly)
- **Multi-threading** - Parallel scan execution for performance
- **Queue Management** - Efficient task distribution and processing

### 🎨 **Enhanced User Experience**
- **ASCII Art Banners** - Metasploit-inspired visual design
- **Colored Progress Bars** - Real-time scan progress with tqdm
- **Comprehensive Help** - Detailed usage examples and timing estimates
- **Structured Logging** - Timestamped execution logs

## � Quick Start

### Lightning-Fast Reconnaissance
```bash
# Ultra-fast scan (completes in <1 second)
./nmap_automator_new.py --lightning 192.168.1.1

# Fast network discovery
./nmap_automator_new.py --fast-scan 192.168.1.0/24

# Quick web services check
./nmap_automator_new.py --web-quick example.com
```

### AI-Powered Analysis
```bash
# Scan with Grok AI analysis
./nmap_automator_new.py --lightning 192.168.1.1 --grok-key YOUR_API_KEY

# OpenAI-powered vulnerability assessment
./nmap_automator_new.py --fast-scan 10.0.0.1 --openai-key YOUR_API_KEY
```

## 📋 Complete Feature Set

### 🎯 **Target Specification**
- Direct IP/hostname targets or load from files with `@` prefix
- Support for `-iL` (input list) and `-iR` (random targets)
- Target exclusion with `--exclude` and `--excludefile`
- Multi-target parallel processing

### � **Scan Techniques**
- **TCP Scans**: SYN (`-sS`), Connect (`-sT`), ACK (`-sA`)
- **Stealth Scans**: NULL (`-sN`), FIN (`-sF`), Xmas (`-sX`)
- **UDP Scanning**: Full UDP port discovery (`-sU`)
- **Custom Combinations**: Mix and match scan types

### 🌐 **Host Discovery**
- **Ping Scans**: ICMP, TCP, UDP discovery methods (`-sn`)
- **List Scans**: Target enumeration without port scanning (`-sL`)
- **Skip Discovery**: Treat all hosts as online (`-Pn`)
- **DNS Control**: Resolution settings (`-n/-R`)
- **Traceroute**: Network path analysis (`--traceroute`)

### 🔌 **Port & Service Detection**
- **Port Ranges**: Flexible specification (`-p22`, `-p1-65535`, `-p80,443`)
- **Fast Mode**: Common ports only (`-F`)
- **Top Ports**: Most common N ports (`--top-ports`)
- **Service Versions**: Detailed service detection (`-sV`)
- **Script Scanning**: NSE integration (`-sC`, `--script`)
- **Version Intensity**: Control detection depth (`--version-intensity`)

### ⚡ **Performance & Timing**
- **Timing Templates**: T0-T5 for speed vs stealth (`-T4`)
- **Rate Control**: Packet rate limits (`--min-rate`, `--max-rate`)
- **Parallel Processing**: Multi-threaded execution (`--threads`)
- **Progress Tracking**: Real-time colored progress bars

### 🛡️ **Evasion & Stealth**
- **Fragmentation**: Packet fragmentation (`-f`)
- **Decoy Scanning**: Hide among decoys (`-D`)
- **Source Spoofing**: Custom source addresses (`-S`)
- **Idle Scanning**: Zombie host scanning (`-sI`)

## 🤖 AI-Powered Analysis

### Intelligent Vulnerability Assessment
- **Grok AI** and **OpenAI** integration for advanced analysis
- **CVE Detection** with severity scoring
- **Metasploit Recommendations** with specific modules
- **Risk Assessment** and remediation guidance

### AI Configuration
```bash
# Using Grok AI (recommended)
export GROK_API_KEY='xai-your-api-key'
./nmap_automator_new.py --lightning target.com --grok-key $GROK_API_KEY

# Using OpenAI
export OPENAI_API_KEY='sk-your-api-key' 
./nmap_automator_new.py --fast-scan target.com --openai-key $OPENAI_API_KEY
```

### Sample AI Analysis
```json
{
  "analysis_summary": "Critical vulnerabilities detected requiring immediate attention",
  "vulnerabilities": [
    {
      "cve": "CVE-2023-XXXXX",
      "severity": "Critical", 
      "exploitability": "High",
      "metasploit_modules": ["exploit/linux/http/apache_mod_cgi"],
      "description": "Remote code execution via HTTP header injection"
    }
  ]
}
```

## 🔗 Tool Chaining

### Nikto Web Scanner Integration
Automatic web vulnerability scanning when web services are discovered:

```bash
# Enable Nikto chaining
./nmap_automator_new.py --web-quick target.com --nikto

# Custom Nikto configuration
./nmap_automator_new.py target.com --nikto --tools-config tools.config.json
```

### Tools Configuration (tools.config.json)
```json
{
  "nikto": {
    "timeout": "600s",
    "format": "json",
    "evasion": "1,2,3",
    "plugins": "headers,cgi,paths"
  }
}
```

## 📅 Scheduling & Automation

### Recurring Scans
```bash
# Schedule hourly scans
./nmap_automator_new.py --schedule 1h --fast-scan 192.168.1.0/24

# Daily comprehensive scans
./nmap_automator_new.py --schedule 1d target.com -sV -sC --script vuln

### Weekly full network audit
./nmap_automator_new.py --schedule 1w @targets.txt --nikto --grok-key $API_KEY
```

## 📊 Performance Benchmarks

### Speed Comparison
| Preset | Time | Ports Scanned | Use Case |
|--------|------|---------------|----------|
| ⚡ Lightning | **0.27s** | Top 20 | Quick reconnaissance |
| 🚀 Fast Scan | **~30s** | Top 100 | Balanced speed/coverage |
| 🌐 Web Quick | **~30s** | Web ports | Service discovery |
| 🥷 Stealth Fast | **~45s** | Top 100 | Evasive scanning |
| 📡 Discovery | **~10s** | Host discovery | Network mapping |
| 🐌 Standard | **7+ min** | All 65,535 ports | Comprehensive audit |

**Performance Improvement: Up to 96.4% faster than standard scans!**

## 🔧 Installation

### Prerequisites
```bash
# Ensure nmap is installed
sudo apt update && sudo apt install nmap nikto

# Install Python dependencies
python3 -m pip install colorama tqdm schedule requests argparse
```

### Quick Install
```bash
# Clone the repository
git clone https://github.com/Mosesjuju/nmap-automator.git
cd nmap-automator

# Set up virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x nmap_automator_new.py

# Test installation
./nmap_automator_new.py --help
```

### Docker Installation
```bash
# Build container
docker build -t nmap-automator .

# Run scans in container
docker run --rm -v $(pwd)/results:/app/nmap_results nmap-automator --lightning 8.8.8.8
```

## 🚀 Usage Examples

### Speed Preset Examples
```bash
# Ultra-fast network reconnaissance
./nmap_automator_new.py --lightning 192.168.1.0/24

# Fast comprehensive scan with AI analysis
./nmap_automator_new.py --fast-scan target.com --grok-key $API_KEY

# Quick web application assessment
./nmap_automator_new.py --web-quick webapp.com --nikto

# Stealth network mapping
./nmap_automator_new.py --stealth-fast 10.0.0.0/16

# Large network host discovery
./nmap_automator_new.py --discovery-only 172.16.0.0/12
```

### Advanced Combinations
```bash
# Scheduled fast scans with AI analysis
./nmap_automator_new.py --schedule 6h --fast-scan @targets.txt --grok-key $API_KEY

# Multi-tool chain scanning
./nmap_automator_new.py --web-quick target.com --nikto --tools-config custom.json

# Comprehensive audit with all features
./nmap_automator_new.py target.com -sV -sC --script vuln --nikto --grok-key $API_KEY
```

### Traditional nmap Examples
```bash
# Stealth SYN scan with version detection
./nmap_automator_new.py example.com -sS -sV -p 80,443

# Comprehensive scan with scripts and OS detection  
./nmap_automator_new.py example.com -A -sC --script vuln -v

# Multiple targets from file
./nmap_automator_new.py @targets.txt -F -T4 --top-ports 100

# Evasion techniques
./nmap_automator_new.py target.com -sS -f -D decoy1,decoy2 --data-length 24

# Dry-run to preview commands
./nmap_automator_new.py example.com -sS -A -p- --script vuln --dry-run
```
    }
  ],
  "metasploit_suggestions": [
    {
      "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
      "description": "Apache mod_cgi Bash Environment Variable Code Injection",
      "usage_notes": "Set RHOST, RPORT, and TARGETURI. Run exploit."
    }
  ]
}
```

#### Benefits
- **Save time**: No manual CVE research required
- **Expert insights**: AI provides penetration testing guidance
- **Actionable results**: Get specific tools and modules to use
- **Comprehensive reports**: JSON format for automation/pipelines

## 📁 Output Structure

### File Organization
```
nmap_results/
├── target_20251022_194627.txt       # Nmap text output
├── target_20251022_194627.xml       # Nmap XML output  
├── target_20251022_194627.xml.analysis.json  # AI analysis
├── nikto_results_target_80.json     # Nikto scan results
└── reports/
    └── target_scan_report.pdf       # Generated reports
```

### Sample Output
```
                    ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
                    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
                    ██╔██╗ ██║██╔████╔██║███████║██████╔╝
                    ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
                    ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
                    ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     

[*] Using LIGHTNING preset: -T5 --top-ports 20 -Pn -n --min-rate 1000
Scanning targets ⚡ [1/1] Network Speed: 0.3 MB/s
[*] Scan completed in 0.27 seconds
[*] Found 3 open ports: 22/ssh, 80/http, 443/https
[*] AI analysis saved to: target_20251022_194627.xml.analysis.json
```

## �️ Configuration

### Environment Variables
```bash
# AI API Keys
export GROK_API_KEY='xai-your-api-key'
export OPENAI_API_KEY='sk-your-api-key'

# Tool Paths
export NMAP_PATH='/usr/bin/nmap'
export NIKTO_PATH='/usr/bin/nikto'
```

### Tools Configuration File
Create `tools.config.json` for advanced tool settings:
```json
{
  "nikto": {
    "path": "/usr/bin/nikto",
    "timeout": "600s", 
    "format": "json",
    "args": "--ssl --Tuning x6",
    "evasion": "1,2,3",
    "plugins": "headers,cgi,paths,robots"
  },
  "ai_analysis": {
    "provider": "grok",
    "model": "grok-beta",
    "timeout": 120,
    "max_retries": 3
  }
}
```

## ⚠️ Legal & Safety

**Important:** Only scan networks and systems you own or have explicit written permission to test.

- **Authorized Testing Only**: Unauthorized scanning may violate laws or policies
- **Use `--dry-run`**: Preview commands before execution
- **Responsible Disclosure**: Report findings through proper channels
- **Rate Limiting**: Use appropriate timing to avoid network disruption

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/nmap-automator.git
cd nmap-automator

# Create feature branch
git checkout -b feature/your-feature-name

# Set up development environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Submit pull request
```

### Areas for Contribution
- 🚀 **Performance Optimization** - New speed presets and techniques
- 🤖 **AI Integrations** - Additional AI providers and analysis methods
- 🔗 **Tool Chaining** - Integration with more security tools
- 📊 **Reporting** - Enhanced output formats and visualizations
- 🛡️ **Evasion Techniques** - Advanced anti-detection methods

## 📚 Documentation

- **[Contributing Guidelines](CONTRIBUTING.md)** - How to contribute to the project
- **[Speed Presets Guide](#-speed-presets---new)** - Performance optimization options
- **[AI Analysis Setup](#-ai-powered-analysis)** - Configure AI vulnerability assessment
- **[Tool Chaining Configuration](#-tool-chaining)** - Integrate with other security tools
- **[Usage Examples](#-usage-examples)** - Comprehensive command examples

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **nmap** - The network exploration tool that makes this all possible
- **Metasploit** - Inspiration for the banner design and security focus
- **OpenAI & xAI** - AI providers enabling intelligent vulnerability analysis
- **Community** - Contributors and users who make this tool better

---

**"The quieter you become, the more you can hear"** 🥷
```

**Custom Nikto configuration:**
```bash
python3 nmap_automator_new.py target.com -sV --nikto-args "--ssl --Tuning 9" --nikto-timeout 300
```

**Using config file:**
```bash
python3 nmap_automator_new.py @targets.txt -sV --tools-config tools.config.json
```

#### Nikto Output
- Displays fancy ASCII banner before scan
- JSON output printed to console
- Can be redirected for processing: `> nikto_results.json`

#### Prerequisites
- Nikto must be installed and in PATH (or specify with `--nikto-path`)
- Install: `sudo apt install nikto` (Debian/Ubuntu) or download from cirt.net

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


## 📘 Developer Guide

See the Developer Guide for design notes, assumptions, and roadmap:

- [DEVELOPER.md](./DEVELOPER.md)



# Extending

If you want additional features such as scheduled scans or a safer interactive authorization prompt, I can add them.
