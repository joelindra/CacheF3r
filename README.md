# CacheF3r

## Advanced Web Cache Poisoning Detection Tool

CacheF3r is a powerful, high-performance scanner designed to detect web cache poisoning vulnerabilities across web applications. By leveraging a comprehensive set of testing techniques, CacheF3r can identify and verify cache-based security issues that might lead to session hijacking, data leakage, or other serious security problems.

## Features

- **Advanced Cache Poisoning Detection**: Specialized in finding 302 redirect-based cache poisoning and other cache vulnerabilities
- **Multi-threaded Scanning**: Parallel processing of targets for high-speed vulnerability detection
- **Intelligent URL Discovery**: Automatic crawling and endpoint discovery
- **Comprehensive Testing**: Tests multiple header variations against each discovered endpoint
- **Vulnerability Verification**: Built-in verification process to eliminate false positives
- **Detailed Reporting**: Generates comprehensive HTML reports with vulnerability details
- **Progress Tracking**: Real-time progress bars and status updates for better visibility
- **Multiple Target Support**: Scan single domains or multiple domains from a list

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/joelindra/CacheF3r.git
   cd CacheF3r
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Dependencies

CacheF3r requires the following Python packages:
```
requests>=2.25.1
colorama>=0.4.4
tqdm>=4.61.0
urllib3>=1.26.5
certifi>=2021.5.30
charset-normalizer>=2.0.0
idna>=3.2
```

## Usage

### Basic Usage

Scan a single domain:
```bash
python cachef3r.py -t example.com
```

Scan multiple domains from a file:
```bash
python cachef3r.py -f targets.txt
```

### Command Line Options

```
usage: cachef3r.py [-h] (-t TARGET | -f FILE) [-j THREADS] [-d DELAY]
                   [-m {standard,aggressive,stealth}] [-o OUTPUT] [-v]
                   [--timeout TIMEOUT]

Enhanced Cache Poisoning Scanner v4.2

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target domain (e.g., example.com or https://example.com)
  -f FILE, --file FILE  File containing list of domains (one per line)
  -j THREADS, --threads THREADS
                        Number of parallel threads (default: 10)
  -d DELAY, --delay DELAY
                        Delay between requests in seconds (default: 1)
  -m {standard,aggressive,stealth}, --mode {standard,aggressive,stealth}
                        Scanning mode (standard, aggressive, stealth)
  -o OUTPUT, --output OUTPUT
                        Output directory (default: cache_scan_[timestamp])
  -v, --verbose         Enable verbose output
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
```

## Example Scan Output

```
═══════════════════════════════════════════════════════════════
║ Enhanced Cache Poisoning Scanner v4.2                       ║
║ Advanced Web Cache Vulnerability Detection                  ║
═══════════════════════════════════════════════════════════════

[INFO]    2025-04-22 15:50:38 │ Validating connection to https://example.com...
[SUCCESS] 2025-04-22 15:50:38 │ Connected to https://example.com (Status: 200)
[INFO]    2025-04-22 15:50:38 │ ═══════════ SCANNING TARGET: example.com ═══════════
[INFO]    2025-04-22 15:50:38 │ Generating payloads for https://example.com...
[SUCCESS] 2025-04-22 15:50:38 │ Generated 17 header types with 73 payload variants
[INFO]    2025-04-22 15:50:38 │ Starting URL discovery for https://example.com...
[PROGRESS] 2025-04-22 15:50:38 │ Added 48 common endpoints as starting points
URL Discovery            100%|████████████████████| 248/248 [00:32<00:00, 7.59url/s, total=248, new=15]
[PROGRESS] 2025-04-22 15:50:71 │ Filtering discovered URLs (248 found)...
Filtering URLs           100%|████████████████████| 248/248 [00:00<00:00, 8273.33url/s, kept=248]
[SUCCESS] 2025-04-22 15:51:12 │ Discovered 248 unique endpoints for example.com
[PROGRESS] 2025-04-22 15:51:12 │ Testing 248 URLs with 73 header variations = 18104 tests
[INFO]    2025-04-22 15:51:12 │ Using 50 parallel threads for testing
Cache Testing            100%|████████████████████| 18104/18104 [23:45<00:00, 12.71test/s]
[SUCCESS] 2025-04-22 16:14:46 │ Found 5 cache poisoning vulnerabilities in example.com
[SUCCESS] 2025-04-22 16:14:46 │ ═════════════════════════════════════════════════════════════════
[SUCCESS] 2025-04-22 16:14:46 │ Completed scan of example.com in 1437.82 seconds
[PROGRESS] 2025-04-22 16:14:47 │ Generating final scan report...
Collecting Results       100%|████████████████████| 1/1 [00:00<00:00, 23.45file/s]
Creating Report          100%|████████████████████| 5/5 [00:01<00:00, 4.17section/s]
[SUCCESS] 2025-04-22 16:14:49 │ Report generated: cache_scan_20250422_155038/report.html
[SUCCESS] 2025-04-22 16:14:49 │ Found 5 verified vulnerabilities!
[INFO]    2025-04-22 16:14:49 │ Check cache_scan_20250422_155038/report.html for detailed results
[SUCCESS] 2025-04-22 16:14:49 │ Scan completed in 1441.37 seconds
```

## Understanding Results

When CacheF3r discovers a vulnerability, it will:

1. Display it in real-time during the scan
2. Include it in the final HTML report
3. Provide verification commands for manual testing

The HTML report contains:
- Summary of all discovered vulnerabilities
- Detailed analysis of each vulnerability
- Affected URLs and headers
- Reflection details
- Manual validation steps
- Recommendations for remediation

## How It Works

CacheF3r operates in several phases:

1. **Target Validation**: Verifies target accessibility and normalizes input
2. **Payload Generation**: Creates various header payloads targeting common cache issues
3. **URL Discovery**: Crawls and identifies endpoints on the target domain
4. **Vulnerability Testing**: Tests each endpoint with multiple header variations
5. **Verification**: Confirms vulnerabilities through multiple validation attempts
6. **Reporting**: Generates a comprehensive HTML report of findings

## Security Notes

- Always obtain proper authorization before scanning any system you don't own
- Some scanning modes may generate significant traffic to target systems
- For production systems, consider using the "stealth" mode and lower thread counts

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning any systems they don't own.
