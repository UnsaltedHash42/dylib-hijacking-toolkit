#!/usr/bin/env python3

import os
import sys
import json
import csv
import logging
import argparse
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
import jinja2
import colorama
from colorama import Fore, Style
import concurrent.futures
from dataclasses import dataclass
from enum import Enum
import tqdm

# Initialize colorama
colorama.init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dylib_scanner.log'),
        logging.StreamHandler()
    ]
)

class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class Vulnerability:
    binary_path: str
    dylib_path: str
    severity: Severity
    description: str
    mitigation: str
    cve_reference: Optional[str] = None
    exploit_complexity: Optional[str] = None
    affected_versions: Optional[List[str]] = None

class DylibHijackScanner:
    def __init__(self, verbose: bool = False, output_dir: str = "reports"):
        self.verbose = verbose
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.vulnerabilities: List[Vulnerability] = []
        self.scanned_paths: Set[str] = set()
        self.template_loader = jinja2.FileSystemLoader(searchpath="./templates")
        self.template_env = jinja2.Environment(loader=self.template_loader)
        
        # Common dylib paths to check
        self.common_dylib_paths = [
            "/usr/lib",
            "/System/Library/Frameworks",
            "/System/Library/PrivateFrameworks",
            "/Library/Frameworks",
            "/opt/homebrew/lib",
            "/usr/local/lib"
        ]

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                    Dylib Hijack Scanner                    ║
║                    Version 2.0                            ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)

    def check_binary(self, binary_path: str) -> List[Vulnerability]:
        """Check a single binary for dylib hijack vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Get binary dependencies
            otool_output = subprocess.check_output(
                ["otool", "-L", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            
            # Parse dependencies
            for line in otool_output.splitlines()[1:]:  # Skip first line
                if "@rpath" in line or "@executable_path" in line:
                    dylib_path = line.split()[0]
                    severity = self._determine_severity(dylib_path, binary_path)
                    
                    vuln = Vulnerability(
                        binary_path=binary_path,
                        dylib_path=dylib_path,
                        severity=severity,
                        description=self._generate_description(dylib_path, binary_path),
                        mitigation=self._generate_mitigation(dylib_path),
                        cve_reference=self._get_cve_reference(dylib_path),
                        exploit_complexity=self._determine_exploit_complexity(dylib_path),
                        affected_versions=self._get_affected_versions()
                    )
                    vulnerabilities.append(vuln)
                    
        except subprocess.CalledProcessError as e:
            if self.verbose:
                logging.error(f"Error checking binary {binary_path}: {e}")
        except Exception as e:
            if self.verbose:
                logging.error(f"Unexpected error checking binary {binary_path}: {e}")
            
        return vulnerabilities

    def _determine_severity(self, dylib_path: str, binary_path: str) -> Severity:
        """Determine the severity of a potential dylib hijack vulnerability."""
        if "@rpath" in dylib_path:
            return Severity.HIGH
        elif "@executable_path" in dylib_path:
            return Severity.MEDIUM
        return Severity.LOW

    def _generate_description(self, dylib_path: str, binary_path: str) -> str:
        """Generate a detailed description of the vulnerability."""
        return f"Potential dylib hijack vulnerability in {binary_path} through {dylib_path}"

    def _generate_mitigation(self, dylib_path: str) -> str:
        """Generate mitigation recommendations."""
        return "Implement proper dylib loading restrictions and code signing"

    def _get_cve_reference(self, dylib_path: str) -> Optional[str]:
        """Get relevant CVE reference if available."""
        # This would be expanded with a database of known vulnerabilities
        return None

    def _determine_exploit_complexity(self, dylib_path: str) -> str:
        """Determine the complexity of exploiting the vulnerability."""
        return "Medium"

    def _get_affected_versions(self) -> List[str]:
        """Get list of affected macOS versions."""
        return [platform.mac_ver()[0]]

    def scan_directory(self, directory: str, max_workers: int = 4):
        """Scan a directory for binaries and check them for vulnerabilities."""
        directory = Path(directory)
        
        if not directory.exists():
            logging.error(f"Directory {directory} does not exist")
            return

        # First, collect all potential binaries
        print(f"{Fore.YELLOW}Collecting potential binaries...{Style.RESET_ALL}")
        binaries = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = Path(root) / file
                try:
                    if self._is_binary(file_path):
                        binaries.append(str(file_path))
                except Exception as e:
                    if self.verbose:
                        logging.error(f"Error checking file {file_path}: {e}")

        if not binaries:
            print(f"{Fore.YELLOW}No binaries found in {directory}{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}Found {len(binaries)} potential binaries to scan{Style.RESET_ALL}")
        
        # Scan binaries with progress bar
        with tqdm.tqdm(total=len(binaries), desc="Scanning binaries", unit="file") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_binary = {executor.submit(self.check_binary, binary): binary 
                                  for binary in binaries}
                
                for future in concurrent.futures.as_completed(future_to_binary):
                    binary = future_to_binary[future]
                    try:
                        vulnerabilities = future.result()
                        self.vulnerabilities.extend(vulnerabilities)
                    except Exception as e:
                        if self.verbose:
                            logging.error(f"Error processing {binary}: {e}")
                    pbar.update(1)

    def _is_binary(self, file_path: Path) -> bool:
        """Check if a file is a binary executable."""
        try:
            # Use subprocess.run with capture_output to handle binary output
            result = subprocess.run(
                ["file", str(file_path)],
                capture_output=True,
                text=True,
                errors='replace'  # Replace invalid characters instead of raising error
            )
            
            if result.returncode != 0:
                return False
                
            return "Mach-O" in result.stdout
        except Exception as e:
            if self.verbose:
                logging.error(f"Error checking if {file_path} is binary: {e}")
            return False

    def generate_reports(self):
        """Generate various report formats."""
        if not self.vulnerabilities:
            print(f"{Fore.YELLOW}No vulnerabilities found to report{Style.RESET_ALL}")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        print(f"{Fore.GREEN}Generating reports...{Style.RESET_ALL}")
        
        # Generate HTML report
        self._generate_html_report(timestamp)
        
        # Generate CSV report
        self._generate_csv_report(timestamp)
        
        # Generate JSON report
        self._generate_json_report(timestamp)
        
        # Generate Markdown report
        self._generate_markdown_report(timestamp)

    def _generate_html_report(self, timestamp: str):
        """Generate an HTML report with interactive elements."""
        template = self.template_env.get_template('report_template.html')
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.html"
        
        with open(report_path, 'w') as f:
            f.write(template.render(
                vulnerabilities=self.vulnerabilities,
                timestamp=timestamp,
                system_info=platform.platform()
            ))

    def _generate_csv_report(self, timestamp: str):
        """Generate a CSV report."""
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.csv"
        
        with open(report_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Binary Path', 'Dylib Path', 'Severity', 'Description', 
                           'Mitigation', 'CVE Reference', 'Exploit Complexity'])
            
            for vuln in self.vulnerabilities:
                writer.writerow([
                    vuln.binary_path,
                    vuln.dylib_path,
                    vuln.severity.value,
                    vuln.description,
                    vuln.mitigation,
                    vuln.cve_reference or '',
                    vuln.exploit_complexity or ''
                ])

    def _generate_json_report(self, timestamp: str):
        """Generate a JSON report."""
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.json"
        
        with open(report_path, 'w') as f:
            json.dump([vars(vuln) for vuln in self.vulnerabilities], f, indent=2)

    def _generate_markdown_report(self, timestamp: str):
        """Generate a Markdown report."""
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.md"
        
        with open(report_path, 'w') as f:
            f.write(f"# Dylib Hijack Scan Report\n\n")
            f.write(f"Generated: {timestamp}\n")
            f.write(f"System: {platform.platform()}\n\n")
            
            for severity in Severity:
                vulns = [v for v in self.vulnerabilities if v.severity == severity]
                if vulns:
                    f.write(f"## {severity.value} Severity Issues\n\n")
                    for vuln in vulns:
                        f.write(f"### {vuln.binary_path}\n")
                        f.write(f"- Dylib: {vuln.dylib_path}\n")
                        f.write(f"- Description: {vuln.description}\n")
                        f.write(f"- Mitigation: {vuln.mitigation}\n")
                        if vuln.cve_reference:
                            f.write(f"- CVE: {vuln.cve_reference}\n")
                        f.write("\n")

def main():
    parser = argparse.ArgumentParser(
        description="Scan for dylib hijack vulnerabilities in macOS binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "directory",
        help="Directory to scan for binaries"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="reports",
        help="Output directory for reports (default: reports)"
    )
    
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=4,
        help="Number of worker threads (default: 4)"
    )
    
    args = parser.parse_args()
    
    scanner = DylibHijackScanner(verbose=args.verbose, output_dir=args.output)
    scanner.print_banner()
    
    print(f"{Fore.GREEN}Starting scan of {args.directory}...{Style.RESET_ALL}")
    scanner.scan_directory(args.directory, max_workers=args.workers)
    
    print(f"{Fore.GREEN}Generating reports...{Style.RESET_ALL}")
    scanner.generate_reports()
    
    print(f"{Fore.GREEN}Scan complete! Reports generated in {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 