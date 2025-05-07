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
import time
from collections import Counter
from collections import defaultdict

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
    why_exploitable: str
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

    def _is_restricted(self, binary_path: str) -> bool:
        """Return True if binary is restricted (hardened runtime, library validation, __RESTRICT, SUID/SGID, or entitlements that block DYLD)."""
        try:
            # Check for __RESTRICT segment
            otool_output = subprocess.check_output(
                ["otool", "-l", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            if "__RESTRICT" in otool_output:
                return True
            # Check SUID/SGID
            st = os.stat(binary_path)
            if bool(st.st_mode & 0o4000) or bool(st.st_mode & 0o2000):
                return True
            # Check code signing flags and entitlements
            cs_info = subprocess.check_output(
                ["codesign", "-dv", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            if "runtime" in cs_info or "library-validation" in cs_info or "restrict" in cs_info:
                return True
            entitlements = subprocess.check_output(
                ["codesign", "-d", "--entitlements", ":-", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            # If the binary has entitlements that block DYLD env vars
            if "com.apple.security.cs.allow-dyld-environment-variables" not in entitlements and (
                "com.apple.security.cs.disable-library-validation" not in entitlements and
                ("com.apple.security.cs.library-validation" in entitlements or "runtime" in cs_info)
            ):
                return True
        except Exception:
            pass
        return False

    def check_binary(self, binary_path: str) -> List[Vulnerability]:
        """Check a single binary for dylib hijack vulnerabilities."""
        vulnerabilities = []
        # Only check if not restricted
        if self._is_restricted(binary_path):
            return []
        try:
            otool_output = subprocess.check_output(
                ["otool", "-l", binary_path],
                universal_newlines=True,
                stderr=subprocess.DEVNULL
            )
            weak_dylibs = self._check_weak_dylibs(binary_path, otool_output)
            vulnerabilities.extend(weak_dylibs)
            rpath_vulns = self._check_rpath_hijacking(binary_path, otool_output)
            vulnerabilities.extend(rpath_vulns)
            reexport_vulns = self._check_reexport_dylibs(binary_path, otool_output)
            vulnerabilities.extend(reexport_vulns)
            upward_vulns = self._check_upward_dylibs(binary_path, otool_output)
            vulnerabilities.extend(upward_vulns)
            dlopen_vulns = self._check_dlopen_hijacking(binary_path, otool_output)
            vulnerabilities.extend(dlopen_vulns)
            # Only check env var hijacking if not a dylib file
            if not binary_path.endswith('.dylib'):
                env_var_vulns = self._check_env_var_hijacking(binary_path)
                vulnerabilities.extend(env_var_vulns)
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
                    why_exploitable="The binary loads a weak dylib that is missing or writable in an unprotected location, allowing an attacker to place a malicious dylib that will be loaded at runtime.",
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
                        why_exploitable="The binary uses an RPATH that is writable or appears earlier in the search order, allowing an attacker to place a malicious dylib that will be loaded before the legitimate one.",
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
                    why_exploitable="The binary re-exports a dylib that does not exist, allowing an attacker to provide a malicious replacement.",
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
                    why_exploitable="The binary loads an upward dylib that does not exist, allowing an attacker to provide a malicious replacement.",
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
                why_exploitable="The binary calls dlopen with a relative or leaf name, allowing an attacker to control which dylib is loaded if the search path is writable.",
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
                    why_exploitable="The binary does not have restrictions that block DYLD_INSERT_LIBRARIES, allowing an attacker to inject a malicious dylib at load time.",
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
                    why_exploitable="The binary is not protected by library validation, allowing unsigned or malicious libraries to be loaded.",
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

        # First, collect all potential file paths
        print(f"{Fore.YELLOW}Collecting files for binary detection...{Style.RESET_ALL}")
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_paths.append(Path(root) / file)

        if not file_paths:
            print(f"{Fore.YELLOW}No files found in {directory}{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}Found {len(file_paths)} files, detecting binaries with {max_workers} workers...{Style.RESET_ALL}")
        binaries = []
        # Parallel binary detection
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for is_bin, file_path in zip(executor.map(self._is_binary, file_paths), file_paths):
                if is_bin:
                    binaries.append(str(file_path))

        if not binaries:
            print(f"{Fore.YELLOW}No binaries found in {directory}{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}Found {len(binaries)} binaries to scan{Style.RESET_ALL}")
        
        start_time = time.time()
        # Scan binaries with progress bar (show ETA)
        with tqdm.tqdm(total=len(binaries), desc="Scanning binaries", unit="file", dynamic_ncols=True, leave=True, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]') as pbar:
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
        end_time = time.time()
        self._print_terminal_summary(start_time, end_time)

    def _print_terminal_summary(self, start_time, end_time):
        """Print a color-coded summary table to the terminal after scan."""
        total = len(self.vulnerabilities)
        counts = Counter([v.severity for v in self.vulnerabilities])
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            color = {
                Severity.CRITICAL: Fore.RED,
                Severity.HIGH: Fore.LIGHTRED_EX,
                Severity.MEDIUM: Fore.YELLOW,
                Severity.LOW: Fore.GREEN,
                Severity.INFO: Fore.CYAN
            }[sev]
            count = counts.get(sev, 0)
            if count > 0:
                print(f"{color}{sev.value:<10}: {count}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Total vulnerabilities: {total}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Scan time: {end_time - start_time:.2f} seconds{Style.RESET_ALL}\n")

    def _is_binary(self, file_path: Path) -> bool:
        """Check if a file is a Mach-O binary by inspecting the magic number."""
        # Only regular files
        if not file_path.is_file():
            return False
        # Mach-O magic numbers (32/64 bit, little/big endian, FAT)
        MACHO_MAGICS = {
            b'\xfe\xed\xfa\xce',  # MH_MAGIC (big-endian 32-bit)
            b'\xce\xfa\xed\xfe',  # MH_CIGAM (little-endian 32-bit)
            b'\xfe\xed\xfa\xcf',  # MH_MAGIC_64 (big-endian 64-bit)
            b'\xcf\xfa\xed\xfe',  # MH_CIGAM_64 (little-endian 64-bit)
            b'\xca\xfe\xba\xbe',  # FAT_MAGIC (big-endian)
            b'\xbe\xba\xfe\xca',  # FAT_CIGAM (little-endian)
        }
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            return magic in MACHO_MAGICS
        except Exception as e:
            if self.verbose:
                logging.error(f"Error reading file header {file_path}: {e}")
            return False

    def generate_reports(self):
        """Generate various report formats, only for vulnerable binaries."""
        # Only keep vulnerabilities for binaries that have at least one vuln
        if not self.vulnerabilities:
            print(f"{Fore.YELLOW}No vulnerabilities found to report{Style.RESET_ALL}")
            return
        # Filter to only binaries with at least one vuln
        vuln_binaries = set(v.binary_path for v in self.vulnerabilities)
        self.vulnerabilities = [v for v in self.vulnerabilities if v.binary_path in vuln_binaries]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(f"{Fore.GREEN}Generating reports...{Style.RESET_ALL}")
        self._generate_html_report(timestamp)
        self._generate_csv_report(timestamp)
        self._generate_json_report(timestamp)
        self._generate_markdown_report(timestamp)
        self._generate_text_report(timestamp)
        self._generate_grepable_report(timestamp)
        self._generate_exploitation_commands(timestamp)

    def _generate_html_report(self, timestamp: str):
        """Generate an HTML report with modern dark mode, grouped by bundle and binary."""
        template = self.template_env.get_template('report_template.html')
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.html"

        # Group vulnerabilities by bundle and binary
        bundles = defaultdict(lambda: defaultdict(list))
        binaries_set = set()
        for vuln in self.vulnerabilities:
            bundle = self._get_bundle_path(vuln.binary_path)
            bundles[bundle][vuln.binary_path].append(vuln)
            binaries_set.add(vuln.binary_path)

        # For summary
        binaries = list(binaries_set)

        with open(report_path, 'w') as f:
            f.write(template.render(
                vulnerabilities=self.vulnerabilities,
                bundles=bundles,
                binaries=binaries,
                timestamp=timestamp,
                system_info=platform.platform()
            ))

    def _get_bundle_path(self, binary_path: str) -> str:
        """Find the .app bundle root for a binary, or use the binary's parent directory."""
        parts = Path(binary_path).parts
        for i in range(len(parts)-1, -1, -1):
            if parts[i].endswith('.app'):
                return str(Path(*parts[:i+1]))
        return str(Path(binary_path).parent)

    def _generate_csv_report(self, timestamp: str):
        """Generate a CSV report."""
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.csv"
        
        with open(report_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Binary Path', 'Dylib Path', 'Severity', 'Vulnerability Type',
                           'Description', 'Mitigation', 'Why Exploitable', 'CVE Reference', 'Exploit Complexity',
                           'Exploitation Command'])
            
            for vuln in self.vulnerabilities:
                writer.writerow([
                    vuln.binary_path,
                    vuln.dylib_path,
                    vuln.severity.value,
                    vuln.vulnerability_type.value,
                    vuln.description,
                    vuln.mitigation,
                    vuln.why_exploitable,
                    vuln.cve_reference or '',
                    vuln.exploit_complexity or '',
                    vuln.exploitation_command or ''
                ])

    def _generate_json_report(self, timestamp: str):
        """Generate a JSON report."""
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.json"
        
        # Convert vulnerabilities to JSON-serializable format
        serializable_vulns = []
        for vuln in self.vulnerabilities:
            vuln_dict = vars(vuln).copy()
            # Convert Enum values to strings
            vuln_dict['severity'] = vuln_dict['severity'].value
            vuln_dict['vulnerability_type'] = vuln_dict['vulnerability_type'].value
            serializable_vulns.append(vuln_dict)
        
        with open(report_path, 'w') as f:
            json.dump(serializable_vulns, f, indent=2)

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
                        f.write(f"- Why Exploitable: {vuln.why_exploitable}\n")
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
        # Notify user
        self._print_terminal_message(f"Exploitation commands saved to {report_path}")

    def _generate_text_report(self, timestamp: str):
        """Generate a plain text report that is terminal-friendly and readable."""
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.txt"
        
        # Group vulnerabilities by bundle and binary
        bundles = {}
        for vuln in self.vulnerabilities:
            bundle = self._get_bundle_path(vuln.binary_path)
            bundles.setdefault(bundle, {})
            bundles[bundle].setdefault(vuln.binary_path, []).append(vuln)
        
        with open(report_path, 'w') as f:
            f.write("=== Dylib Hijack Scan Report ===\n")
            f.write(f"Generated: {timestamp}\n")
            f.write(f"System: {platform.platform()}\n\n")
            # Summary
            total_vulns = len(self.vulnerabilities)
            counts = Counter([v.severity.value for v in self.vulnerabilities])
            f.write("--- Summary ---\n")
            f.write(f"Total Bundles: {len(bundles)}\n")
            f.write(f"Total Binaries: {len(set(v.binary_path for v in self.vulnerabilities))}\n")
            f.write(f"Total Vulnerabilities: {total_vulns}\n")
            for sev in ['Critical','High','Medium','Low','Info']:
                if counts.get(sev, 0):
                    f.write(f"{sev}: {counts[sev]}\n")
            f.write("\n")
            # Details
            for bundle, bins in bundles.items():
                f.write(f"Bundle: {bundle}\n")
                for binary, vulns in bins.items():
                    top = max(v.severity.value for v in vulns)
                    f.write(f"  Binary: {binary} (Highest: {top})\n")
                    for i, v in enumerate(vulns,1):
                        f.write(f"    [{i}] {v.vulnerability_type.value} - {v.severity.value}\n")
                        f.write(f"        Dylib: {v.dylib_path}\n")
                        f.write(f"        Desc: {v.description}\n")
                        f.write(f"        Mitigation: {v.mitigation}\n")
                        f.write(f"        Why Exploitable: {v.why_exploitable}\n")
                        if v.exploit_complexity: f.write(f"        Exploit Complexity: {v.exploit_complexity}\n")
                        if v.cve_reference: f.write(f"        CVE: {v.cve_reference}\n")
                f.write("\n")
        self._print_terminal_message(f"Text report saved to {report_path}")

    def _generate_grepable_report(self, timestamp: str):
        """Generate a grepable report: one vulnerability per line, tab-separated."""
        report_path = self.output_dir / f"dylib_scan_report_{timestamp}.grep"
        with open(report_path, 'w') as f:
            f.write("Bundle\tBinary\tSeverity\tType\tDylib\tDescription\tMitigation\tWhy_Exploitable\tExploit_Complexity\tCVE\n")
            for v in self.vulnerabilities:
                bundle = self._get_bundle_path(v.binary_path)
                fields = [
                    bundle, v.binary_path, v.severity.value, v.vulnerability_type.value,
                    v.dylib_path,
                    v.description.replace('\t',' ').replace('\n',' '),
                    v.mitigation.replace('\t',' ').replace('\n',' '),
                    v.why_exploitable.replace('\t',' ').replace('\n',' '),
                    v.exploit_complexity or 'N/A', v.cve_reference or 'N/A'
                ]
                f.write("\t".join(fields)+"\n")
        self._print_terminal_message(f"Grepable report saved to {report_path}")

    def _print_terminal_message(self, message: str):
        """Print a colorized message to the terminal."""
        print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

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