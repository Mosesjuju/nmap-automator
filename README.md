# NMAP Automator v2.0 - Python Package Edition



A modern, robust, and extensible Python package for automated network scanning using Nmap and Masscan.

## Features
- Fast and flexible scanning with Nmap and Masscan
- XML parsing and result extraction
- Robust error handling and logging
- Professional package structure
- Zero known syntax, import, or runtime errors

## Usage

### Install Locally
```
pip install .
```

### Run as a Module
```
python -m nmap_automator scanme.nmap.org
```

### Scan Specific Ports
```
python -m nmap_automator scanme.nmap.org -p 1-1000
```

### Fast Scan (Top 100 ports)
```
python -m nmap_automator scanme.nmap.org --scan-type "-F"
```

### Use Masscan for Discovery
```
python -m nmap_automator scanme.nmap.org --masscan
```

### Save Results to Custom Directory
```
python -m nmap_automator scanme.nmap.org --outdir results
```

### Disable XML Output
```
python -m nmap_automator scanme.nmap.org --no-xml
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
