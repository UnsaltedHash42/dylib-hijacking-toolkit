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
import re
import shutil

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

class VulnerabilityType(Enum):
    WEAK_DYLIB = "Weak Dylib"
    RPATH_HIJACKING = "RPATH Hijacking"
    LIBRARY_VALIDATION = "Library Validation"
    ENV_VAR_HIJACKING = "Environment Variable Hijacking"
    REEXPORT_DYLIB = "Re-export Dylib"
    UPWARD_DYLIB = "Upward Dylib"
    DLOPEN_HIJACKING = "dlopen Hijacking"

@dataclass
class Vulnerability:
    binary_path: str
    dylib_path: str
    severity: Severity
    vulnerability_type: VulnerabilityType
    description: str
    mitigation: str
    cve_reference: Optional[str] = None
    exploit_complexity: Optional[str] = None
    affected_versions: Optional[List[str]] = None
    exploitation_command: Optional[str] = None
    rpath_search_order: Optional[List[str]] = None
    amfi_flags: Optional[Dict[str, bool]] = None

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
            # Get binary dependencies with all load commands
            otool_output = subprocess.check_output(
                ["otool", "-l", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            
            # Check for weak dylibs
            weak_dylibs = self._check_weak_dylibs(binary_path, otool_output)
            vulnerabilities.extend(weak_dylibs)
            
            # Check for rpath hijacking
            rpath_vulns = self._check_rpath_hijacking(binary_path, otool_output)
            vulnerabilities.extend(rpath_vulns)
            
            # Check for re-export dylibs
            reexport_vulns = self._check_reexport_dylibs(binary_path, otool_output)
            vulnerabilities.extend(reexport_vulns)
            
            # Check for upward dylibs
            upward_vulns = self._check_upward_dylibs(binary_path, otool_output)
            vulnerabilities.extend(upward_vulns)
            
            # Check for dlopen hijacking
            dlopen_vulns = self._check_dlopen_hijacking(binary_path, otool_output)
            vulnerabilities.extend(dlopen_vulns)
            
            # Check for environment variable hijacking
            env_var_vulns = self._check_env_var_hijacking(binary_path)
            vulnerabilities.extend(env_var_vulns)
            
            # Check for library validation issues
            lib_val_vulns = self._check_library_validation(binary_path)
            vulnerabilities.extend(lib_val_vulns)
            
        except subprocess.CalledProcessError as e:
            if self.verbose:
                logging.error(f"Error checking binary {binary_path}: {e}")
        except Exception as e:
            if self.verbose:
                logging.error(f"Unexpected error checking binary {binary_path}: {e}")
            
        return vulnerabilities

    def _check_weak_dylibs(self, binary_path: str, otool_output: str) -> List[Vulnerability]:
        """Check for weak dylib vulnerabilities."""
        vulnerabilities = []
        
        # Extract LC_LOAD_WEAK_DYLIB commands with version info
        weak_dylibs = re.findall(r'LC_LOAD_WEAK_DYLIB.*?name (.*?) \(.*?current version (.*?)\n.*?compatibility version (.*?)\n', otool_output)
        
        for dylib, current_version, compat_version in weak_dylibs:
            if not dylib.startswith('@'):
                # Check if path is writable
                dylib_path = os.path.expanduser(dylib)
                is_writable = os.access(os.path.dirname(dylib_path), os.W_OK)
                
                # Check if path is SIP protected
                is_sip_protected = any(protected_path in dylib_path for protected_path in [
                    '/System/Library',
                    '/usr/lib',
                    '/usr/local/lib',
                    '/opt/homebrew/lib'
                ])
                
                # Check if dylib exists and get its version
                dylib_exists = os.path.exists(dylib_path)
                dylib_version = None
                if dylib_exists:
                    try:
                        dylib_otool = subprocess.check_output(
                            ["otool", "-l", dylib_path],
                            universal_newlines=True,
                            stderr=subprocess.DEVNULL
                        )
                        version_match = re.search(r'current version (.*?)\n', dylib_otool)
                        if version_match:
                            dylib_version = version_match.group(1)
                    except subprocess.CalledProcessError:
                        pass
                
                # Determine severity based on conditions
                severity = Severity.HIGH
                if is_sip_protected:
                    severity = Severity.LOW
                elif not is_writable:
                    severity = Severity.MEDIUM
                
                vuln = Vulnerability(
                    binary_path=binary_path,
                    dylib_path=dylib,
                    severity=severity,
                    vulnerability_type=VulnerabilityType.WEAK_DYLIB,
                    description=f"Missing weak dylib: {dylib} (Current version: {current_version}, Compat version: {compat_version})",
                    mitigation="Implement proper dylib loading restrictions and code signing",
                    exploit_complexity="Medium" if is_writable else "High",
                    affected_versions=[platform.mac_ver()[0]],
                    amfi_flags={
                        "is_writable": is_writable,
                        "is_sip_protected": is_sip_protected,
                        "dylib_exists": dylib_exists,
                        "dylib_version": dylib_version,
                        "required_version": current_version,
                        "compat_version": compat_version
                    }
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _check_rpath_hijacking(self, binary_path: str, otool_output: str) -> List[Vulnerability]:
        """Check for RPATH hijacking vulnerabilities."""
        vulnerabilities = []
        
        # Extract RPATH commands and their order
        rpaths = re.findall(r'LC_RPATH.*?path (.*?) \(', otool_output)
        
        if rpaths:
            # Check each RPATH in order
            for i, rpath in enumerate(rpaths):
                rpath = os.path.expanduser(rpath)
                
                # Check if RPATH is writable
                is_writable = os.access(rpath, os.W_OK)
                
                # Check if RPATH is SIP protected
                is_sip_protected = any(protected_path in rpath for protected_path in [
                    '/System/Library',
                    '/usr/lib',
                    '/usr/local/lib',
                    '/opt/homebrew/lib'
                ])
                
                # Check if RPATH exists and is a directory
                rpath_exists = os.path.exists(rpath)
                is_directory = os.path.isdir(rpath) if rpath_exists else False
                
                # Check if RPATH is absolute or relative
                is_absolute = os.path.isabs(rpath)
                
                # Determine severity based on conditions
                severity = Severity.HIGH
                if is_sip_protected:
                    severity = Severity.LOW
                elif not is_writable:
                    severity = Severity.MEDIUM
                
                # Only report if RPATH is writable or in an earlier position
                if is_writable or i < len(rpaths) - 1:
                    vuln = Vulnerability(
                        binary_path=binary_path,
                        dylib_path=rpath,
                        severity=severity,
                        vulnerability_type=VulnerabilityType.RPATH_HIJACKING,
                        description=f"RPATH hijacking possible: {rpath} (Position {i+1} of {len(rpaths)})",
                        mitigation="Use @rpath with proper restrictions or remove unnecessary RPATHs",
                        exploit_complexity="Medium" if is_writable else "High",
                        affected_versions=[platform.mac_ver()[0]],
                        amfi_flags={
                            "is_writable": is_writable,
                            "is_sip_protected": is_sip_protected,
                            "rpath_exists": rpath_exists,
                            "is_directory": is_directory,
                            "is_absolute": is_absolute,
                            "position": i + 1,
                            "total_rpaths": len(rpaths)
                        }
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _check_reexport_dylibs(self, binary_path: str, otool_output: str) -> List[Vulnerability]:
        """Check for re-export dylib vulnerabilities."""
        vulnerabilities = []
        
        # Extract LC_REEXPORT_DYLIB commands
        reexport_dylibs = re.findall(r'LC_REEXPORT_DYLIB.*?name (.*?) \(', otool_output)
        
        for dylib in reexport_dylibs:
            if not os.path.exists(dylib) and not dylib.startswith('@'):
                vuln = Vulnerability(
                    binary_path=binary_path,
                    dylib_path=dylib,
                    severity=Severity.HIGH,
                    vulnerability_type=VulnerabilityType.REEXPORT_DYLIB,
                    description=f"Re-export dylib vulnerability: {dylib}",
                    mitigation="Implement proper dylib loading restrictions and code signing",
                    exploit_complexity="High",
                    affected_versions=[platform.mac_ver()[0]]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _check_upward_dylibs(self, binary_path: str, otool_output: str) -> List[Vulnerability]:
        """Check for upward dylib vulnerabilities."""
        vulnerabilities = []
        
        # Extract LC_LOAD_UPWARD_DYLIB commands
        upward_dylibs = re.findall(r'LC_LOAD_UPWARD_DYLIB.*?name (.*?) \(', otool_output)
        
        for dylib in upward_dylibs:
            if not os.path.exists(dylib) and not dylib.startswith('@'):
                vuln = Vulnerability(
                    binary_path=binary_path,
                    dylib_path=dylib,
                    severity=Severity.HIGH,
                    vulnerability_type=VulnerabilityType.UPWARD_DYLIB,
                    description=f"Upward dylib vulnerability: {dylib}",
                    mitigation="Implement proper dylib loading restrictions and code signing",
                    exploit_complexity="High",
                    affected_versions=[platform.mac_ver()[0]]
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _check_dlopen_hijacking(self, binary_path: str, otool_output: str) -> List[Vulnerability]:
        """Check for dlopen hijacking vulnerabilities."""
        vulnerabilities = []
        
        # Check for hardened runtime
        has_hardened_runtime = False
        try:
            codesign_output = subprocess.check_output(
                ["codesign", "-d", "--verbose=4", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            has_hardened_runtime = "runtime" in codesign_output
        except subprocess.CalledProcessError:
            pass
        
        # Check for __RESTRICT segment
        has_restrict_segment = "__RESTRICT" in otool_output
        
        # Check for library validation entitlement
        has_library_validation = True
        try:
            codesign_output = subprocess.check_output(
                ["codesign", "-d", "--entitlements", ":-", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            has_library_validation = "com.apple.security.cs.disable-library-validation" not in codesign_output
        except subprocess.CalledProcessError:
            pass
        
        # Extract dlopen calls with relative paths or leaf names
        dlopen_calls = re.findall(r'LC_LOAD_DYLIB.*?name (.*?) \(', otool_output)
        
        for dylib in dlopen_calls:
            # Skip @rpath and absolute paths
            if dylib.startswith('@') or os.path.isabs(dylib):
                continue
            
            # Check if path is writable
            dylib_path = os.path.expanduser(dylib)
            is_writable = os.access(os.path.dirname(dylib_path), os.W_OK)
            
            # Check if path is SIP protected
            is_sip_protected = any(protected_path in dylib_path for protected_path in [
                '/System/Library',
                '/usr/lib',
                '/usr/local/lib',
                '/opt/homebrew/lib'
            ])
            
            # Determine severity based on conditions
            severity = Severity.HIGH
            if has_hardened_runtime and has_library_validation:
                severity = Severity.LOW
            elif is_sip_protected:
                severity = Severity.MEDIUM
            elif not is_writable:
                severity = Severity.MEDIUM
            
            vuln = Vulnerability(
                binary_path=binary_path,
                dylib_path=dylib,
                severity=severity,
                vulnerability_type=VulnerabilityType.DLOPEN_HIJACKING,
                description=f"Potential dlopen hijacking: {dylib}",
                mitigation="Use absolute paths or implement proper dylib loading restrictions",
                exploit_complexity="Medium" if is_writable else "High",
                affected_versions=[platform.mac_ver()[0]],
                amfi_flags={
                    "is_writable": is_writable,
                    "is_sip_protected": is_sip_protected,
                    "has_hardened_runtime": has_hardened_runtime,
                    "has_restrict_segment": has_restrict_segment,
                    "has_library_validation": has_library_validation
                }
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _check_env_var_hijacking(self, binary_path: str) -> List[Vulnerability]:
        """Check for environment variable hijacking vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for __RESTRICT segment
            otool_output = subprocess.check_output(
                ["otool", "-l", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            
            has_restrict = "__RESTRICT" in otool_output
            
            # Check entitlements
            entitlements = subprocess.check_output(
                ["codesign", "-d", "--entitlements", ":-", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            
            has_lib_validation = "com.apple.security.cs.library-validation" in entitlements
            has_disable_lib_validation = "com.apple.security.cs.disable-library-validation" in entitlements
            
            # Check setuid/setgid
            st = os.stat(binary_path)
            has_setuid = bool(st.st_mode & 0o4000)
            has_setgid = bool(st.st_mode & 0o2000)
            
            if not has_restrict and not has_lib_validation and not has_disable_lib_validation and not (has_setuid or has_setgid):
                vuln = Vulnerability(
                    binary_path=binary_path,
                    dylib_path="DYLD_INSERT_LIBRARIES",
                    severity=Severity.HIGH,
                    vulnerability_type=VulnerabilityType.ENV_VAR_HIJACKING,
                    description="Environment variable hijacking possible",
                    mitigation="Enable library validation and hardened runtime",
                    exploit_complexity="Low",
                    affected_versions=[platform.mac_ver()[0]],
                    exploitation_command=f"DYLD_INSERT_LIBRARIES=/path/to/malicious.dylib {binary_path}",
                    amfi_flags={
                        "has_restrict": has_restrict,
                        "has_lib_validation": has_lib_validation,
                        "has_disable_lib_validation": has_disable_lib_validation,
                        "has_setuid": has_setuid,
                        "has_setgid": has_setgid
                    }
                )
                vulnerabilities.append(vuln)
                
        except subprocess.CalledProcessError:
            pass
            
        return vulnerabilities

    def _check_library_validation(self, binary_path: str) -> List[Vulnerability]:
        """Check for library validation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check code signing
            cs_info = subprocess.check_output(
                ["codesign", "-dv", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            
            has_hardened_runtime = "runtime" in cs_info
            has_library_validation = "library-validation" in cs_info
            
            if not has_library_validation:
                vuln = Vulnerability(
                    binary_path=binary_path,
                    dylib_path="N/A",
                    severity=Severity.HIGH,
                    vulnerability_type=VulnerabilityType.LIBRARY_VALIDATION,
                    description="Missing library validation",
                    mitigation="Enable library validation in code signing",
                    exploit_complexity="Medium",
                    affected_versions=[platform.mac_ver()[0]]
                )
                vulnerabilities.append(vuln)
                
        except subprocess.CalledProcessError:
            pass
            
        return vulnerabilities

    def _resolve_rpath(self, rpath: str, binary_path: str) -> Optional[str]:
        """Resolve an rpath to an absolute path."""
        if rpath.startswith('@loader_path'):
            return os.path.dirname(binary_path)
        elif rpath.startswith('@executable_path'):
            return os.path.dirname(binary_path)
        else:
            return rpath

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
        
        # Generate exploitation commands
        self._generate_exploitation_commands(timestamp)

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
            writer.writerow(['Binary Path', 'Dylib Path', 'Severity', 'Vulnerability Type',
                           'Description', 'Mitigation', 'CVE Reference', 'Exploit Complexity',
                           'Exploitation Command'])
            
            for vuln in self.vulnerabilities:
                writer.writerow([
                    vuln.binary_path,
                    vuln.dylib_path,
                    vuln.severity.value,
                    vuln.vulnerability_type.value,
                    vuln.description,
                    vuln.mitigation,
                    vuln.cve_reference or '',
                    vuln.exploit_complexity or '',
                    vuln.exploitation_command or ''
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
                        f.write(f"- Type: {vuln.vulnerability_type.value}\n")
                        f.write(f"- Dylib: {vuln.dylib_path}\n")
                        f.write(f"- Description: {vuln.description}\n")
                        f.write(f"- Mitigation: {vuln.mitigation}\n")
                        if vuln.cve_reference:
                            f.write(f"- CVE: {vuln.cve_reference}\n")
                        if vuln.exploitation_command:
                            f.write(f"- Exploitation: {vuln.exploitation_command}\n")
                        if vuln.rpath_search_order:
                            f.write(f"- RPATH Search Order:\n")
                            for path in vuln.rpath_search_order:
                                f.write(f"  - {path}\n")
                        f.write("\n")

    def _generate_exploitation_commands(self, timestamp: str):
        """Generate exploitation commands for vulnerable binaries."""
        report_path = self.output_dir / f"exploitation_commands_{timestamp}.txt"
        
        with open(report_path, 'w') as f:
            f.write("# Exploitation Commands\n\n")
            
            for vuln in self.vulnerabilities:
                if vuln.exploitation_command:
                    f.write(f"# {vuln.binary_path}\n")
                    f.write(f"# Type: {vuln.vulnerability_type.value}\n")
                    f.write(f"# Severity: {vuln.severity.value}\n")
                    f.write(f"{vuln.exploitation_command}\n\n")

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