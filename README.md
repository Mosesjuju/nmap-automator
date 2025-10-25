# NMAP Automator v2.0 - Python Package Edition



A modern, robust, and extensible Python package for automated network scanning using Nmap and Masscan.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
python -m nmap_automator <Ip addr> -p 1-1000
```


### Fast Scan (Top 100 ports)
```
python -m nmap_automator <Ip addr> --scan-type "-F"
```


### Use Masscan for Discovery
```
python -m nmap_automator <Ip addr> --masscan
```


### Save Results to Custom Directory
```
python -m nmap_automator <Ip addr> --outdir results
```


### Disable XML Output
```
python -m nmap_automator <Ip addr> --no-xml
```


### Save and View Results as HTML
After scanning, you will be prompted to save results as `.txt`, `.xml`, or `.html`. If you choose `.html`, you can view the file with:
```
xdg-open results/<Ip addr>.html
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
MIT License

Copyright (c) 2025 Mosesjuju

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
