# 🔍 SecureScout Directory Structure

## 📁 Project Organization

```
NMAP/                                   # SecureScout Root Directory
├── 📁 core/                           # Core scanning engine modules
│   ├── nmap_automator_optimized.py   # Main scanning engine (optimized)
│   ├── async_scan_engine.py          # Asynchronous scanning capabilities
│   └── evasion_profiles.py           # Network evasion techniques
│
├── 📁 tools/                          # Scanning tools and utilities
│   ├── performance_optimizer.py       # Smart caching & performance optimization
│   ├── vuln_analyzer.py              # Vulnerability analysis tools
│   ├── tool_chain.py                 # Tool integration chain
│   ├── burp_integration.py           # Burp Suite integration
│   ├── nmap_automator_new.py         # Enhanced automator features
│   └── webmap_scanner.py             # Web mapping capabilities
│
├── 📁 scripts/                        # Execution & utility scripts
│   ├── run_securescout.sh            # Main launcher script (auto-venv)
│   ├── securescout.py                # Python launcher
│   ├── cloud_quickstart.sh           # Cloud deployment quickstart
│   ├── cloud_scanning_demo.py        # Cloud scanning demonstrations
│   └── cloud_transformation.py       # Cloud transformation utilities
│
├── 📁 config/                         # Configuration files
│   ├── config.json                   # Main configuration
│   ├── scan_profiles.json            # Scanning profiles
│   └── evasion_config.json           # Evasion configurations
│
├── 📁 results/                        # Scan results & outputs
│   ├── cloud_results/                # Cloud assessment results
│   ├── nmap_results/                 # Nmap scan outputs
│   ├── test_results/                 # Test scan results
│   ├── tool_results/                 # Tool-specific outputs
│   ├── webmap_results/               # Web mapping results
│   └── *.txt, *.md                   # Individual scan files
│
├── 📁 tests/                          # Test suites & validation
│   ├── test_smart_cache.py           # Smart caching system tests
│   ├── test_imports.py               # Import validation tests
│   ├── test_nmap_automator.py        # Core functionality tests
│   ├── test_ascii.py                 # ASCII art tests
│   └── ci_test_reports/              # CI/CD test reports
│
├── 📁 logs/                           # Application logs
│   ├── nmap_automator.log            # Main application log
│   └── transformation_log.txt        # Cloud transformation logs
│
├── 📁 cache/                          # Smart caching system
│   └── cache_persistence.json        # Persistent cache storage
│
├── 📁 backup/                         # Backup files & versions
│   └── [previous versions]           # Historical backups
│
├── 📁 docs/                           # Documentation
│   ├── API_documentation.md          # API reference
│   ├── configuration_guide.md        # Configuration guide
│   ├── CHANGELOG.md                  # Version changelog
│   └── [other docs]                  # Additional documentation
│
├── 📁 temp/                           # Temporary files (cleanup needed)
│   ├── backup_v1.2.1/               # Old backup version
│   ├── __pycache__/                  # Python cache files
│   └── [large binary files]         # Files to be cleaned
│
├── 📁 .venv/                          # Python virtual environment
│   ├── bin/                          # Virtual env executables
│   ├── lib/                          # Installed packages
│   └── pyvenv.cfg                    # Virtual env configuration
│
└── 📄 Project Files                   # Root level files
    ├── README.md                      # Main project documentation
    ├── PROJECT_STRUCTURE.md           # Legacy structure doc
    ├── SMART_CACHING_GUIDE.md         # Smart caching user guide
    ├── SMART_CACHE_IMPLEMENTATION.md  # Technical implementation details
    ├── DEBUG_RESOLUTION_REPORT.md     # Debugging resolution report
    ├── requirements.txt               # Python dependencies (basic)
    ├── requirements-fixed.txt         # Python dependencies (with versions)
    └── DIRECTORY_STRUCTURE.md         # This document
```

## 🔧 Quick Access Commands

### Activate Environment & Run
```bash
cd /home/kali/NMAP
source .venv/bin/activate
./scripts/run_securescout.sh
```

### Smart Caching Test
```bash
cd /home/kali/NMAP
source .venv/bin/activate
python tests/test_smart_cache.py
```

### View Logs
```bash
tail -f logs/nmap_automator.log
```

### Check Cache Performance
```bash
cat cache/cache_persistence.json | jq '.metadata'
```

## 📊 Directory Size & Organization

- **Core Engine**: 6 optimized modules
- **Tools**: 7 specialized scanning tools
- **Scripts**: 5 execution & utility scripts
- **Results**: Organized by scan type and date
- **Tests**: Comprehensive test coverage
- **Smart Cache**: Persistent intelligent caching
- **Virtual Environment**: Isolated dependency management

## 🚀 Performance Features

- ✅ Smart Caching (911.6x performance improvement)
- ✅ Adaptive TTL & Priority-based eviction
- ✅ Cross-session persistence (70+ cache entries)
- ✅ Virtual environment isolation
- ✅ Automated dependency management
- ✅ Comprehensive logging & analytics

---
*Generated: October 23, 2025 | SecureScout v2.0 Smart Cache Enhanced*