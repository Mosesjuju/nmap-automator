# NMAP Automator v1.1.1 - Burp Suite Integration Examples

## 🔥 Burp Suite Professional Integration

NMAP Automator now includes comprehensive Burp Suite Professional integration for automated web application security testing.

### Prerequisites
1. **Burp Suite Professional** (Community Edition does not support REST API)
2. **REST API Enabled** in Burp Suite
3. **API Running** on localhost:1337 (default)

### Setup Instructions

#### 1. Enable Burp Suite REST API
```bash
# Start Burp Suite Professional
# Go to User Options > Misc > REST API
# Check "Enable REST API"
# Set API Port: 1337 (default)
# Optional: Set API Key for authentication
```

#### 2. Basic Usage Examples

```bash
# Enable Burp Suite scanning for web services
./nmap_automator_new.py --burp scanme.nmap.org -p 80,443

# Combine with tool chaining
./nmap_automator_new.py --burp --select-tools nikto,gobuster target.com

# Custom Burp configuration
./nmap_automator_new.py --burp \
  --burp-scan-type active \
  --burp-crawl-strategy most_complete \
  --burp-max-crawl-time 600 \
  --burp-max-audit-time 1800 \
  target.com -p 80,443

# Use with masscan fast scanning
./nmap_automator_new.py --masscan-fast --burp --chain-tools target.com
```

#### 3. Advanced Configuration

```bash
# Custom Burp Suite instance
./nmap_automator_new.py --burp \
  --burp-host 192.168.1.100 \
  --burp-port 8080 \
  --burp-api-key "your-api-key" \
  target.com

# Passive scanning only (faster, less intrusive)
./nmap_automator_new.py --burp \
  --burp-scan-type passive \
  --burp-crawl-strategy fast \
  target.com

# Crawl-only mode for site mapping
./nmap_automator_new.py --burp \
  --burp-scan-type crawl_only \
  --burp-crawl-strategy most_complete \
  --burp-max-crawl-time 900 \
  target.com
```

### Integration Features

#### 🎯 **Automatic Web Service Detection**
- Automatically detects HTTP/HTTPS services from nmap scans
- Constructs proper URLs with protocols and ports
- Initiates Burp scans only for web services

#### 🚀 **Intelligent Workflow**
```
1. Nmap Discovery → 2. Tool Chaining → 3. Burp Suite Scanning
     ↓                    ↓                     ↓
   Port 80 Open      nikto scan           Automated Web
   Port 443 Open     gobuster enum        Application Audit
   HTTP Service      sslscan check        Vulnerability Detection
```

#### 📊 **Professional Reporting**
- HTML reports generated automatically
- JSON/XML export available  
- Saved to `burp_results/` directory
- Timestamped for easy tracking

#### 🔄 **Background Processing**
- Non-blocking scan execution
- Real-time progress monitoring
- Automatic cleanup on completion

### Scan Types Explained

| Scan Type | Description | Use Case | Time |
|-----------|-------------|----------|------|
| `active` | Full crawl + vulnerability testing | Complete security audit | 15-30min |
| `passive` | Analysis without active testing | Safe reconnaissance | 5-10min |
| `crawl_only` | Site mapping and discovery | Application mapping | 5-15min |

### Crawl Strategies

| Strategy | Description | Coverage | Speed |
|----------|-------------|----------|--------|
| `fast` | Basic crawling, common paths | Low | High |
| `thorough` | Comprehensive crawling | Medium | Medium |
| `most_complete` | Exhaustive discovery | High | Low |

### Example Workflows

#### 🔥 **Enterprise Security Assessment**
```bash
# Complete security platform workflow
./nmap_automator_new.py \
  --masscan-fast \
  --chain-tools \
  --burp \
  --burp-scan-type active \
  --burp-crawl-strategy most_complete \
  --burp-max-audit-time 1800 \
  --grok-key $GROK_API_KEY \
  target-network.com/24

# Result: 
# 1. Ultra-fast port discovery (masscan)
# 2. Service enumeration (nmap) 
# 3. Tool chaining (nikto, gobuster, sslscan)
# 4. Professional web app testing (Burp Suite)
# 5. AI-powered vulnerability analysis (Grok)
```

#### 🥷 **Stealth Assessment**
```bash
# Low-profile security testing
./nmap_automator_new.py \
  --stealth-fast \
  --burp \
  --burp-scan-type passive \
  --burp-crawl-strategy fast \
  target.com

# Result: Minimal footprint with professional analysis
```

#### 🚀 **Bug Bounty Reconnaissance**
```bash
# Comprehensive bug bounty workflow
./nmap_automator_new.py \
  --lightning \
  --select-tools nikto,gobuster,dnsrecon \
  --burp \
  --burp-scan-type active \
  scope-targets.txt

# Result: Fast discovery with deep web application analysis
```

### Output Structure

```
project/
├── nmap_results/
│   ├── target_20251023_073000.txt       # Nmap results
│   ├── target_20251023_073000.xml       # XML for WebMap
│   └── target_20251023_073000.xml.analysis.json  # AI analysis
├── tool_results/
│   ├── nikto_target_1761217000.txt      # Tool chain results
│   ├── gobuster_target_1761217001.txt
│   └── sslscan_target_1761217002.txt
├── burp_results/
│   ├── burp_report_task123_1761217100.html  # Burp Suite reports
│   ├── burp_report_task124_1761217200.json
│   └── scan_metrics.json
└── nmap_automator.log                    # Execution logs
```

### Troubleshooting

#### Common Issues

1. **"Burp Suite API not available"**
```bash
# Check Burp Suite is running
# Verify REST API is enabled in User Options > Misc
# Confirm port 1337 is accessible
netstat -an | grep 1337
```

2. **Authentication errors**
```bash
# Set API key if required
./nmap_automator_new.py --burp --burp-api-key "your-key" target.com
```

3. **Scan timeouts**
```bash
# Increase timeout values
./nmap_automator_new.py --burp \
  --burp-max-crawl-time 900 \
  --burp-max-audit-time 2700 \
  target.com
```

### Performance Recommendations

#### For Large Applications
```bash
./nmap_automator_new.py --burp \
  --burp-crawl-strategy thorough \
  --burp-max-crawl-time 1800 \
  --burp-max-audit-time 3600 \
  large-app.com
```

#### For Quick Assessment  
```bash
./nmap_automator_new.py --burp \
  --burp-scan-type passive \
  --burp-crawl-strategy fast \
  --burp-max-crawl-time 180 \
  target.com
```

### Security Best Practices

1. **Authorization**: Only test applications you own or have permission to test
2. **Rate Limiting**: Use appropriate timeouts to avoid overwhelming targets
3. **Scope Management**: Define clear testing boundaries  
4. **Result Handling**: Securely store and manage scan results

### Integration Benefits

✅ **Professional Grade**: Industry-standard web application testing  
✅ **Seamless Workflow**: Integrated with nmap discovery and tool chaining  
✅ **Automated Reporting**: Comprehensive vulnerability reports  
✅ **Background Processing**: Non-blocking execution  
✅ **AI Enhancement**: Combined with Grok analysis for expert insights  
✅ **Enterprise Ready**: Production-quality security assessment platform

---

**"From network discovery to application security - the complete security testing platform"** 🔥

For more information, see the main documentation or run:
```bash
./nmap_automator_new.py --help | grep -A 20 "Burp Suite"
```