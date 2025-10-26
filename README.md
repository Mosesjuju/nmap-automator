
# Nmap Automator

Automated Nmap and Masscan scanning tool for efficient network reconnaissance.

## Features

- Fast and automated scanning using Nmap and Masscan
- Output parsing and reporting
- Progress bars and colored output (tqdm, colorama)
- Extensible and robust Python 3.7+ codebase
- Advanced smart caching system for scan results



## Get Started in Minutes

Skip manual installation! Use the automated setup script for a quick start:

```bash
./run_in_venv.sh <target_ip> [options]
```

This script will:
- Create a Python virtual environment
- Install all dependencies
- Run Nmap Automator with your chosen options

No manual pip or package management required.



## Usage

### Recommended: Run in a virtual environment

```bash
./run_in_venv.sh <target_ip> [options]
```
This script will set up a Python virtual environment, install dependencies, and run Nmap Automator.

### Manual usage

If you prefer manual setup, use:
```bash
sudo python3 -m nmap_automator <target_ip> [options]
```
Replace `<target_ip>` with the IP address or hostname you want to scan.

### Arguments
- `--fast-scan` : Run a quick scan using Masscan and Nmap top ports
- `--full-scan` : Run a comprehensive scan of all ports
- `--output <file>` : Save results to a file
- `--cache` : Enable smart caching for scan results
- `--no-cache` : Disable caching
- `--json` : Output results in JSON format
- `--help` : Show help message

## Smart Cache System

Nmap Automator includes a smart caching system to avoid redundant scans and speed up repeated operations.

- **Automatic Caching**: Scan results are cached by target IP and scan type.
- **Cache Directory**: Cached results are stored in `nmap_results/` by default.
- **Cache Validation**: Before running a scan, the tool checks for valid cached results and reuses them if available.
- **Manual Control**: Use `--no-cache` to force a fresh scan, or `--cache` to enable caching.
- **Cache Expiry**: Cached results can be set to expire after a configurable time (see config options).
- **Cache Format**: Results are stored in both human-readable and JSON formats for easy reuse.

## Requirements

- Python 3.7+
- Nmap
- Masscan
- tqdm
- colorama

See `requirements.txt` for Python dependencies.

## Project Structure

- `nmap_automator/` : Main package code
- `nmap_automator/automator.py` : Core logic and scan orchestration
- `nmap_automator/__main__.py` : Entry point for CLI usage
- `nmap_results/` : Default cache directory for scan results
- `requirements.txt` : Python dependencies
- `LICENSE` : MIT License

## License

MIT — see the [LICENSE](LICENSE) file for details.

## Documentation

- For advanced usage, configuration, and cache system details, see:
	- [SMART_CACHE_IMPLEMENTATION.md](SMART_CACHE_IMPLEMENTATION.md)
	- [SMART_CACHING_GUIDE.md](SMART_CACHING_GUIDE.md)
	- [docs/README.md](docs/README.md)

---
