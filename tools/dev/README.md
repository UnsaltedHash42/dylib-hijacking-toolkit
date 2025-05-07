# Dylib Hijack Scanner

A powerful tool for detecting dylib hijack vulnerabilities in macOS binaries. This scanner helps security researchers and red teamers identify potential dylib hijacking opportunities in macOS applications.

## Features

- Scans directories for Mach-O binaries
- Detects potential dylib hijack vulnerabilities
- Multi-threaded scanning for improved performance
- Comprehensive reporting in multiple formats:
  - Interactive HTML reports
  - CSV exports
  - JSON exports
  - Markdown reports
- Severity classification of vulnerabilities
- Exploit complexity assessment
- CVE reference tracking
- Affected version tracking
- Detailed mitigation recommendations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/dylib-hijack-scanner.git
cd dylib-hijack-scanner
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python dylib_hijack_scanner.py /path/to/scan
```

Advanced options:
```bash
python dylib_hijack_scanner.py /path/to/scan -v -o reports -w 8
```

### Command Line Arguments

- `directory`: Directory to scan for binaries (required)
- `-v, --verbose`: Enable verbose output
- `-o, --output`: Output directory for reports (default: reports)
- `-w, --workers`: Number of worker threads (default: 4)

## Report Formats

The scanner generates multiple report formats in the specified output directory:

1. **HTML Report** (`dylib_scan_report_TIMESTAMP.html`)
   - Interactive table with sorting and filtering
   - Severity-based color coding
   - Detailed vulnerability cards
   - Summary statistics

2. **CSV Report** (`dylib_scan_report_TIMESTAMP.csv`)
   - Comma-separated values for easy import into spreadsheets
   - Contains all vulnerability details

3. **JSON Report** (`dylib_scan_report_TIMESTAMP.json`)
   - Machine-readable format
   - Complete vulnerability data structure

4. **Markdown Report** (`dylib_scan_report_TIMESTAMP.md`)
   - Human-readable format
   - Organized by severity level
   - Suitable for documentation

## Vulnerability Assessment

The scanner assesses vulnerabilities based on several factors:

1. **Severity Levels**:
   - Critical
   - High
   - Medium
   - Low
   - Info

2. **Exploit Complexity**:
   - Low
   - Medium
   - High

3. **Mitigation Recommendations**:
   - Code signing requirements
   - Library loading restrictions
   - Path validation
   - Additional security measures

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and security research purposes only. Always obtain proper authorization before scanning systems. The authors are not responsible for any misuse or damage caused by this tool. 