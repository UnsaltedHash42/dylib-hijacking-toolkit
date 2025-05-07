#!/bin/bash
#
# Dylib Hijacking Scanner
#
# This script scans applications for potential dylib hijacking vulnerabilities
# It identifies:
# 1. Binaries with LC_LOAD_WEAK_DYLIB that could be hijacked
# 2. Binaries with @rpath dependencies where search order can be exploited
# 3. Code signing restrictions that may prevent exploitation
# 4. Environment variable (DYLD_INSERT_LIBRARIES) hijacking vulnerabilities
#

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}      Dylib Hijacking Vulnerability Scanner          ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Directory to scan
if [ -z "$1" ]; then
    SCAN_DIR="/Applications"
    echo -e "${YELLOW}[!] No directory specified, using default: ${SCAN_DIR}${NC}"
else
    SCAN_DIR="$1"
    echo -e "${GREEN}[+] Scanning directory: ${SCAN_DIR}${NC}"
fi

# Check if directory exists
if [ ! -d "$SCAN_DIR" ]; then
    echo -e "${RED}[!] Directory does not exist: ${SCAN_DIR}${NC}"
    exit 1
fi

# Timestamp for log files
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create output directory
OUTPUT_DIR="dylib_scan_results_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Log files
MASTER_LOG="${OUTPUT_DIR}/master_report.txt"
SUMMARY_LOG="${OUTPUT_DIR}/summary_report.txt"
WEAK_DYLIBS_LOG="${OUTPUT_DIR}/weak_dylibs_vulnerabilities.txt"
RPATH_LOG="${OUTPUT_DIR}/rpath_vulnerabilities.txt"
LIBRARY_VALIDATION_LOG="${OUTPUT_DIR}/library_validation_vulnerabilities.txt"
ENV_VAR_LOG="${OUTPUT_DIR}/environment_variable_vulnerabilities.txt"
EXECUTABLE_LIST="${OUTPUT_DIR}/scanned_executables.txt"
CONSOLE_LOG="${OUTPUT_DIR}/console_output.txt"

# Create temporary directory for results
TEMP_DIR=$(mktemp -d)
MACHO_LIST="${TEMP_DIR}/macho_list.txt"

# Function to find all Mach-O binaries in a directory
find_macho_files() {
    echo -e "${GREEN}[+] Finding Mach-O files in ${SCAN_DIR}...${NC}" | tee -a "$CONSOLE_LOG"
    
    # Initialize macOS-compatible find command that will correctly handle spaces and special characters
    # Search for executable binaries and common dylib patterns first
    find "$SCAN_DIR" -type f \( -name "*.dylib" -o -name "*.bundle" -o -path "*/MacOS/*" \) 2>/dev/null > "$MACHO_LIST"
    
    # Create a temporary file to store additional Mach-O files
    TEMP_MACHO="${TEMP_DIR}/temp_macho.txt"
    > "$TEMP_MACHO"
    
    # Process each found file to verify it's a Mach-O
    local total_found=0
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            file_type=$(file "$file" 2>/dev/null)
            if [[ "$file_type" == *"Mach-O"* ]]; then
                echo "$file" >> "$TEMP_MACHO"
                total_found=$((total_found + 1))
            fi
        fi
    done < "$MACHO_LIST"
    
    # Replace the original list with verified Mach-O files
    mv "$TEMP_MACHO" "$MACHO_LIST"
    
    # If we found fewer than 5 Mach-O files, use a more aggressive but slower search
    if [ "$total_found" -lt 5 ]; then
        echo -e "${YELLOW}[!] Few Mach-O files found, using deeper search...${NC}" | tee -a "$CONSOLE_LOG"
        TEMP_DEEP="${TEMP_DIR}/deep_macho.txt"
        
        # Find all files first
        find "$SCAN_DIR" -type f -not -path "*/\.*" -not -path "*/Resources/*.png" -not -path "*/Resources/*.jpg" 2>/dev/null | while IFS= read -r file; do
            if [ -f "$file" ]; then
                file_type=$(file "$file" 2>/dev/null)
                if [[ "$file_type" == *"Mach-O"* ]]; then
                    echo "$file" >> "$TEMP_DEEP"
                fi
            fi
        done
        
        # Append unique results to our main list
        if [ -f "$TEMP_DEEP" ]; then
            sort "$TEMP_DEEP" | uniq > "${TEMP_DIR}/unique_deep.txt"
            cat "${TEMP_DIR}/unique_deep.txt" >> "$MACHO_LIST"
            sort "$MACHO_LIST" | uniq > "${TEMP_DIR}/final_list.txt"
            mv "${TEMP_DIR}/final_list.txt" "$MACHO_LIST"
        fi
    fi
    
    # Get the final count
    local binary_count=$(wc -l < "$MACHO_LIST" | xargs)
    
    # Check if we found any Mach-O files
    if [ "$binary_count" -eq 0 ]; then
        # Last resort - try the most aggressive search for specific app structure
        echo -e "${YELLOW}[!] No Mach-O files found yet, trying last resort search...${NC}" | tee -a "$CONSOLE_LOG"
        
        # Check if we're scanning an .app bundle and look for its executable
        if [[ "$SCAN_DIR" == *".app"* ]]; then
            APP_NAME=$(basename "$SCAN_DIR" .app)
            APP_MACOS_DIR="${SCAN_DIR}/Contents/MacOS"
            
            if [ -d "$APP_MACOS_DIR" ]; then
                # Look for executable with same name as the app
                if [ -f "${APP_MACOS_DIR}/${APP_NAME}" ]; then
                    file_type=$(file "${APP_MACOS_DIR}/${APP_NAME}" 2>/dev/null)
                    if [[ "$file_type" == *"Mach-O"* ]]; then
                        echo "${APP_MACOS_DIR}/${APP_NAME}" >> "$MACHO_LIST"
                    fi
                fi
                
                # Check all files in MacOS directory
                find "$APP_MACOS_DIR" -type f 2>/dev/null | while IFS= read -r file; do
                    file_type=$(file "$file" 2>/dev/null)
                    if [[ "$file_type" == *"Mach-O"* ]]; then
                        echo "$file" >> "$MACHO_LIST"
                    fi
                done
            fi
        fi
    fi
    
    # Final sanity check and deduplication
    if [ -f "$MACHO_LIST" ]; then
        sort "$MACHO_LIST" | uniq > "${TEMP_DIR}/final_list.txt"
        mv "${TEMP_DIR}/final_list.txt" "$MACHO_LIST"
    fi
    
    local binary_count=$(wc -l < "$MACHO_LIST" | xargs)
    echo -e "${GREEN}[+] Found ${binary_count} Mach-O binaries${NC}" | tee -a "$CONSOLE_LOG"
    
    return $binary_count
}

# Function to check if a binary has LC_LOAD_WEAK_DYLIB commands
check_weak_dylibs() {
    local binary="$1"
    local binary_name=$(basename "$binary")
    
    echo -e "${GREEN}[+] Checking for weak dylibs in ${binary_name}${NC}" | tee -a "$CONSOLE_LOG"
    
    # Get all LC_LOAD_WEAK_DYLIB references
    otool -l "$binary" 2>/dev/null | grep -A 3 "LC_LOAD_WEAK_DYLIB" | grep "name" | awk '{print $2}' > "${TEMP_DIR}/${binary_name}_weak.txt"
    
    local vulnerable=false
    
    if [ -s "${TEMP_DIR}/${binary_name}_weak.txt" ]; then
        echo -e "\n==== Weak Dylib Analysis for $binary ====" >> "$MASTER_LOG"
        echo -e "Weak Dylibs for $binary:" >> "$MASTER_LOG"
        
        while read -r lib; do
            # Check if library exists
            if [ ! -f "$lib" ] && [[ ! "$lib" == @* ]]; then
                echo -e "${RED}    [-] ${lib} (DOES NOT EXIST - POTENTIAL HIJACK TARGET)${NC}" | tee -a "$CONSOLE_LOG"
                echo "  - $lib (DOES NOT EXIST - POTENTIAL HIJACK TARGET)" >> "$MASTER_LOG"
                
                # Add to weak dylibs vulnerability log
                echo "$binary|$lib|MISSING_WEAK_DYLIB" >> "$WEAK_DYLIBS_LOG"
                vulnerable=true
            else
                echo -e "    ${lib}" | tee -a "$CONSOLE_LOG"
                echo "  - $lib (exists)" >> "$MASTER_LOG"
            fi
        done < "${TEMP_DIR}/${binary_name}_weak.txt"
    else
        echo -e "  No weak dylibs found" >> "$MASTER_LOG"
    fi
    
    rm "${TEMP_DIR}/${binary_name}_weak.txt" 2>/dev/null
    
    if [ "$vulnerable" = true ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to resolve application directory path
resolve_app_dir() {
    local dir="$1"
    local app_dir="$dir"
    
    # Walk up the directory tree until we find a .app directory or reach root
    while [[ ! "$app_dir" == *".app"* && "$app_dir" != "/" ]]; do
        app_dir=$(dirname "$app_dir")
    done
    
    # If we reached root without finding a .app directory, return the original path
    if [[ "$app_dir" == "/" ]]; then
        echo "$dir"
    else
        echo "$app_dir"
    fi
}

# Function to check for @rpath dependencies
check_rpath_deps() {
    local binary="$1"
    local binary_name=$(basename "$binary")
    
    echo -e "${GREEN}[+] Checking for @rpath dependencies in ${binary_name}${NC}" | tee -a "$CONSOLE_LOG"
    
    # Get all @rpath references
    otool -l "$binary" 2>/dev/null | grep -A 3 "LC_LOAD_DYLIB" | grep "name" | grep "@rpath" | awk '{print $2}' > "${TEMP_DIR}/${binary_name}_rpath.txt"
    
    local vulnerable=false
    
    if [ -s "${TEMP_DIR}/${binary_name}_rpath.txt" ]; then
        echo -e "\n==== RPATH Analysis for $binary ====" >> "$MASTER_LOG"
        echo -e "RPATH Dependencies:" >> "$MASTER_LOG"
        
        while read -r lib; do
            echo "  - $lib" >> "$MASTER_LOG"
        done < "${TEMP_DIR}/${binary_name}_rpath.txt"
        
        # Get LC_RPATH commands
        echo -e "RPATH Search Paths:" >> "$MASTER_LOG"
        rpaths=$(otool -l "$binary" 2>/dev/null | grep -A 2 "LC_RPATH" | grep "path" | awk '{print $2}')
        
        if [ ! -z "$rpaths" ]; then
            local is_first=true
            local first_rpath=""
            local dylib_found=false
            
            echo -e "${YELLOW}[!] RPATH search order:${NC}" | tee -a "$CONSOLE_LOG"
            
            for rpath in $rpaths; do
                # Resolve @loader_path or @executable_path if possible
                local resolved_path=""
                if [[ "$rpath" == @loader_path* ]]; then
                    bin_dir=$(dirname "$binary")
                    resolved_path="${rpath/@loader_path/$bin_dir}"
                    echo -e "    ${rpath} -> ${resolved_path}" | tee -a "$CONSOLE_LOG"
                    echo "  - ${rpath} -> ${resolved_path}" >> "$MASTER_LOG"
                elif [[ "$rpath" == @executable_path* ]]; then
                    bin_dir=$(dirname "$binary")
                    app_dir=$(resolve_app_dir "$bin_dir")
                    resolved_path="${rpath/@executable_path/$app_dir}"
                    echo -e "    ${rpath} -> ${resolved_path}" | tee -a "$CONSOLE_LOG"
                    echo "  - ${rpath} -> ${resolved_path}" >> "$MASTER_LOG"
                else
                    echo -e "    ${rpath}" | tee -a "$CONSOLE_LOG"
                    echo "  - ${rpath}" >> "$MASTER_LOG"
                    resolved_path="$rpath"
                fi
                
                # Check if this is the first path in the search order
                if $is_first; then
                    first_rpath=$resolved_path
                    is_first=false
                fi
                
                # Check for rpath-based dylibs in this location
                while read -r dylib; do
                    # Extract just the filename part from @rpath/name.dylib
                    dylib_name=${dylib/@rpath\//}
                    
                    if [[ ! -z "$resolved_path" && "$resolved_path" != "" ]]; then
                        full_path="${resolved_path}/${dylib_name}"
                        
                        if [ -f "$full_path" ]; then
                            dylib_found=true
                            echo -e "    Found ${dylib_name} at ${full_path}" | tee -a "$CONSOLE_LOG"
                            echo "  - Found ${dylib_name} at ${full_path}" >> "$MASTER_LOG"
                        fi
                    fi
                done < "${TEMP_DIR}/${binary_name}_rpath.txt"
            done
            
            # Check for potential hijacking via rpath ordering
            if ! $dylib_found && [ ! -z "$first_rpath" ]; then
                echo -e "${RED}    [!] Potential RPATH hijacking: First search path doesn't contain required dylibs${NC}" | tee -a "$CONSOLE_LOG"
                echo "  - VULNERABLE: First search path doesn't contain required dylibs" >> "$MASTER_LOG"
                
                while read -r dylib; do
                    dylib_name=${dylib/@rpath\//}
                    echo "$binary|$first_rpath/$dylib_name|RPATH_HIJACKING" >> "$RPATH_LOG"
                    vulnerable=true
                done < "${TEMP_DIR}/${binary_name}_rpath.txt"
            fi
        else
            echo -e "    No LC_RPATH commands found" | tee -a "$CONSOLE_LOG"
            echo "  - No LC_RPATH commands found" >> "$MASTER_LOG"
        fi
    else
        echo -e "  No @rpath dependencies found" >> "$MASTER_LOG"
    fi
    
    rm "${TEMP_DIR}/${binary_name}_rpath.txt" 2>/dev/null
    
    if [ "$vulnerable" = true ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to check code signing restrictions
check_code_signing() {
    local binary="$1"
    local binary_name=$(basename "$binary")
    
    echo -e "${GREEN}[+] Checking code signing for ${binary_name}${NC}" | tee -a "$CONSOLE_LOG"
    
    echo -e "\n==== Code Signing Analysis for $binary ====" >> "$MASTER_LOG"
    
    # Check code signing
    local cs_info=$(codesign -dv "$binary" 2>&1)
    local has_hardened_runtime=false
    local has_library_validation=false
    local has_disable_lib_validation=false
    local lib_validation_vulnerable=false
    
    if echo "$cs_info" | grep -q "runtime"; then
        echo -e "${RED}    [-] Has hardened runtime${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - Has hardened runtime" >> "$MASTER_LOG"
        has_hardened_runtime=true
    else
        echo "  - No hardened runtime" >> "$MASTER_LOG"
    fi
    
    if echo "$cs_info" | grep -q "library-validation"; then
        echo -e "${RED}    [-] Has library validation${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - Has library validation" >> "$MASTER_LOG"
        has_library_validation=true
    else
        echo -e "${YELLOW}    [!] No library validation - potential target${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - VULNERABLE: No library validation" >> "$MASTER_LOG"
        
        # Add to library validation vulnerability log
        echo "$binary|MISSING_LIBRARY_VALIDATION" >> "$LIBRARY_VALIDATION_LOG"
        lib_validation_vulnerable=true
    fi
    
    # Check entitlements
    local entitlements=$(codesign -dv --entitlements - "$binary" 2>&1)
    if echo "$entitlements" | grep -q "disable-library-validation"; then
        echo -e "${YELLOW}    [!] Has disable-library-validation entitlement - potential target${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - VULNERABLE: Has disable-library-validation entitlement" >> "$MASTER_LOG"
        
        # Add to library validation vulnerability log
        echo "$binary|DISABLED_LIBRARY_VALIDATION" >> "$LIBRARY_VALIDATION_LOG"
        
        has_disable_lib_validation=true
        lib_validation_vulnerable=true
    fi
    
    if [ "$lib_validation_vulnerable" = true ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Function to check if binary is vulnerable to environment variable-based hijacking
# Function to check if binary is vulnerable to environment variable-based hijacking
# Function to check if binary is vulnerable to environment variable-based hijacking
# Function to check if binary is vulnerable to environment variable-based hijacking
check_env_var_hijacking() {
    local binary="$1"
    local binary_name=$(basename "$binary")

    # Skip shared libraries—DYLD_INSERT_LIBRARIES only affects executables at launch
    if [[ "$binary" == *.dylib ]]; then
        echo -e "${BLUE}    [i] Skipping env var hijack check for shared library${NC}" | tee -a "$CONSOLE_LOG"
        echo "false"
        return
    fi

    echo -e "${GREEN}[+] Checking for environment variable hijacking vulnerability in ${binary_name}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "\n==== Environment Variable Hijacking Analysis for $binary ====" >> "$MASTER_LOG"

    # Capture codesign info once
    local cs_info
    cs_info=$(codesign -dv "$binary" 2>&1)

    # If Hardened Runtime is enabled, DYLD_INSERT_LIBRARIES is blocked by default
    if echo "$cs_info" | grep -q "(runtime)"; then
        echo -e "${RED}    [-] Has hardened runtime - protected from environment variable hijacking${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - Has hardened runtime - cannot exploit with DYLD_INSERT_LIBRARIES" >> "$MASTER_LOG"
        echo "false"
        return
    fi

    # If library validation is enabled, this binary is protected
    if echo "$cs_info" | grep -q "library-validation"; then
        echo -e "${RED}    [-] Has library validation - protected from environment variable hijacking${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - Has library validation - cannot exploit with DYLD_INSERT_LIBRARIES" >> "$MASTER_LOG"
        echo "false"
        return
    fi

    # Initialize vulnerability status
    local is_vulnerable=true

    # Check for __RESTRICT segment
    if otool -l "$binary" 2>/dev/null | grep -q "__RESTRICT"; then
        echo -e "${RED}    [-] Has __RESTRICT segment - protected from environment variable hijacking${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - Has __RESTRICT segment - protected from environment variable hijacking" >> "$MASTER_LOG"
        is_vulnerable=false
    else
        echo -e "${GREEN}    [+] No __RESTRICT segment${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - No __RESTRICT segment found" >> "$MASTER_LOG"
    fi

    # Check setuid/setgid bits
    if [ -u "$binary" ] || [ -g "$binary" ]; then
        echo -e "${RED}    [-] Has setuid/setgid bits - protected from environment variable hijacking${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - Has setuid/setgid bits - protected from environment variable hijacking" >> "$MASTER_LOG"
        is_vulnerable=false
    else
        echo -e "${GREEN}    [+] No setuid/setgid bits${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - No setuid/setgid bits" >> "$MASTER_LOG"
    fi

    # Save raw codesign output for debugging
    echo "  - Raw codesign output:" >> "$MASTER_LOG"
    echo "$cs_info" | sed 's/^/    /' >> "$MASTER_LOG"

    # Check for CS_RESTRICT flag (prevents env var hijacking)
    if echo "$cs_info" | grep -q "restrict"; then
        echo -e "${RED}    [-] Has CS_RESTRICT flag - protected from environment variable hijacking${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - Has CS_RESTRICT flag - protected from environment variable hijacking" >> "$MASTER_LOG"
        is_vulnerable=false
    else
        echo -e "${GREEN}    [+] No CS_RESTRICT flag${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - No CS_RESTRICT flag" >> "$MASTER_LOG"
    fi

    # Report final vulnerability assessment
    if [ "$is_vulnerable" = true ]; then
        echo -e "${YELLOW}    [!] Vulnerable to environment variable hijacking (DYLD_INSERT_LIBRARIES)${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - VULNERABLE: Can be exploited with DYLD_INSERT_LIBRARIES" >> "$MASTER_LOG"

        # Add to environment variable vulnerability log
        echo "$binary|DYLD_INSERT_LIBRARIES|ENV_VAR_HIJACKING" >> "$ENV_VAR_LOG"

        # Add example exploitation command to the log
        echo "  - Example exploitation: DYLD_INSERT_LIBRARIES=/path/to/malicious.dylib $binary" >> "$MASTER_LOG"

        echo "true"
    else
        echo -e "  - NOT VULNERABLE to environment variable hijacking" >> "$MASTER_LOG"
        echo "false"
    fi
}




# Main function
main() {
    echo -e "${GREEN}[+] Starting scan...${NC}" | tee -a "$CONSOLE_LOG"
    
    # Initialize log files
    echo "Dylib Hijacking Vulnerability Scan" > "$MASTER_LOG"
    echo "====================================" >> "$MASTER_LOG"
    echo "Date: $(date)" >> "$MASTER_LOG"
    echo "Target directory: $SCAN_DIR" >> "$MASTER_LOG"
    echo "====================================" >> "$MASTER_LOG"
    
    echo "# Vulnerable Binaries - Missing or Non-Existent Weak Dylibs" > "$WEAK_DYLIBS_LOG"
    echo "# Format: binary_path|dylib_path|vulnerability_type" >> "$WEAK_DYLIBS_LOG"
    echo "" >> "$WEAK_DYLIBS_LOG"
    
    echo "# Vulnerable Binaries - RPATH Hijacking Opportunities" > "$RPATH_LOG"
    echo "# Format: binary_path|potential_hijack_path|vulnerability_type" >> "$RPATH_LOG"
    echo "" >> "$RPATH_LOG"
    
    echo "# Vulnerable Binaries - Library Validation Issues" > "$LIBRARY_VALIDATION_LOG"
    echo "# Format: binary_path|vulnerability_type" >> "$LIBRARY_VALIDATION_LOG"
    echo "" >> "$LIBRARY_VALIDATION_LOG"
    
    echo "# Vulnerable Binaries - Environment Variable Hijacking" > "$ENV_VAR_LOG"
    echo "# Format: binary_path|environment_variable|vulnerability_type" >> "$ENV_VAR_LOG"
    echo "" >> "$ENV_VAR_LOG"
    
    echo "# List of All Scanned Executables" > "$EXECUTABLE_LIST"
    echo "" >> "$EXECUTABLE_LIST"
    
    # Find Mach-O files
    find_macho_files
    binary_count=$?
    
    if [ "$binary_count" -eq 0 ]; then
        echo -e "${RED}[-] No Mach-O files found in ${SCAN_DIR}${NC}" | tee -a "$CONSOLE_LOG"
        echo "No Mach-O files found." >> "$MASTER_LOG"
        rm -rf "$TEMP_DIR"
        rm -rf "$OUTPUT_DIR"  # Clean up output directory since we have no results
        exit 1
    fi
    
    # Variables to track vulnerability counts
    weak_vuln_count=0
    rpath_vuln_count=0
    libval_vuln_count=0
    envvar_vuln_count=0
    total_vuln_count=0
    total_binaries=0
    
    # Process each binary
    while read -r binary; do
        # Skip non-existent files (sometimes file command can produce odd output)
        if [ ! -f "$binary" ]; then
            continue
        fi
        
        total_binaries=$((total_binaries + 1))
        echo "$binary" >> "$EXECUTABLE_LIST"
        
        echo "===============================================================" | tee -a "$CONSOLE_LOG"
        echo -e "${BLUE}Analyzing: ${binary}${NC}" | tee -a "$CONSOLE_LOG"
        
        # Check for different vulnerability types
        weak_vulnerable=$(check_weak_dylibs    "$binary" | tail -n1)
        rpath_vulnerable=$(check_rpath_deps    "$binary" | tail -n1)
        libval_vulnerable=$(check_code_signing "$binary" | tail -n1)
        envvar_vulnerable=$(check_env_var_hijacking "$binary" | tail -n1)

        
        # Debug output
        echo "Debug - weak_vulnerable: $weak_vulnerable" >> "$MASTER_LOG"
        echo "Debug - rpath_vulnerable: $rpath_vulnerable" >> "$MASTER_LOG" 
        echo "Debug - libval_vulnerable: $libval_vulnerable" >> "$MASTER_LOG"
        echo "Debug - envvar_vulnerable: $envvar_vulnerable" >> "$MASTER_LOG"
        
        # Count vulnerabilities for this binary
        binary_vulnerable=false
        
        if [ "$weak_vulnerable" = "true" ]; then
            weak_vuln_count=$((weak_vuln_count + 1))
            binary_vulnerable=true
        fi
        
        if [ "$rpath_vulnerable" = "true" ]; then
            rpath_vuln_count=$((rpath_vuln_count + 1))
            binary_vulnerable=true
        fi
        
        if [ "$libval_vulnerable" = "true" ]; then
            libval_vuln_count=$((libval_vuln_count + 1))
            binary_vulnerable=true
        fi
        
        if [ "$envvar_vulnerable" = "true" ]; then
            envvar_vuln_count=$((envvar_vuln_count + 1))
            binary_vulnerable=true
        fi
        
        if [ "$binary_vulnerable" = "true" ]; then
            total_vuln_count=$((total_vuln_count + 1))
        fi
        
    done < "$MACHO_LIST"
    
    # Print summary
    echo "===============================================================" | tee -a "$CONSOLE_LOG"
    echo -e "${BLUE}Scan Complete - Summary${NC}" | tee -a "$CONSOLE_LOG"
    
    echo -e "${GREEN}[+] Total analyzed binaries: ${total_binaries}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Total potentially vulnerable binaries: ${total_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Weak dylib vulnerabilities: ${weak_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] RPATH ordering vulnerabilities: ${rpath_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Library validation vulnerabilities: ${libval_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Environment variable hijacking vulnerabilities: ${envvar_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    
    # Create summary report
    echo "Dylib Hijacking Vulnerability Scan Summary" > "$SUMMARY_LOG"
    echo "==========================================" >> "$SUMMARY_LOG"
    echo "Date: $(date)" >> "$SUMMARY_LOG"
    echo "Target directory: $SCAN_DIR" >> "$SUMMARY_LOG"
    echo "==========================================" >> "$SUMMARY_LOG"
    echo "" >> "$SUMMARY_LOG"
    echo "OVERALL STATISTICS:" >> "$SUMMARY_LOG"
    echo "Total analyzed binaries: ${total_binaries}" >> "$SUMMARY_LOG"
    echo "Total potentially vulnerable binaries: ${total_vuln_count}" >> "$SUMMARY_LOG"
    echo "Weak dylib vulnerabilities: ${weak_vuln_count}" >> "$SUMMARY_LOG"
    echo "RPATH ordering vulnerabilities: ${rpath_vuln_count}" >> "$SUMMARY_LOG"
    echo "Library validation vulnerabilities: ${libval_vuln_count}" >> "$SUMMARY_LOG"
    echo "Environment variable hijacking vulnerabilities: ${envvar_vuln_count}" >> "$SUMMARY_LOG"
    echo "" >> "$SUMMARY_LOG"
    
    # Add vulnerability details if any found
    if [ $weak_vuln_count -gt 0 ]; then
        echo "WEAK DYLIB VULNERABILITIES:" >> "$SUMMARY_LOG"
        echo "These binaries reference weak dylibs that don't exist and could be hijacked:" >> "$SUMMARY_LOG"
        grep -v "^#" "$WEAK_DYLIBS_LOG" | cut -d'|' -f1,2 | sort | uniq | sed 's/|/ -> /g' >> "$SUMMARY_LOG"
        echo "" >> "$SUMMARY_LOG"
    fi
    
    if [ $rpath_vuln_count -gt 0 ]; then
        echo "RPATH ORDERING VULNERABILITIES:" >> "$SUMMARY_LOG"
        echo "These binaries could be exploited through rpath search order:" >> "$SUMMARY_LOG"
        grep -v "^#" "$RPATH_LOG" | cut -d'|' -f1,2 | sort | uniq | sed 's/|/ -> /g' >> "$SUMMARY_LOG"
        echo "" >> "$SUMMARY_LOG"
    fi
    
    if [ $libval_vuln_count -gt 0 ]; then
        echo "LIBRARY VALIDATION VULNERABILITIES:" >> "$SUMMARY_LOG"
        echo "These binaries have missing or disabled library validation:" >> "$SUMMARY_LOG"
        grep -v "^#" "$LIBRARY_VALIDATION_LOG" | cut -d'|' -f1,2 | sort | uniq | sed 's/|/ -> /g' >> "$SUMMARY_LOG"
        echo "" >> "$SUMMARY_LOG"
    fi
    
     if [ $envvar_vuln_count -gt 0 ]; then
        echo "ENVIRONMENT VARIABLE HIJACKING VULNERABILITIES:" >> "$SUMMARY_LOG"
        echo "These binaries can be exploited with DYLD_INSERT_LIBRARIES:" >> "$SUMMARY_LOG"
        grep -v "^#" "$ENV_VAR_LOG" \
            | cut -d'|' -f1,2 \
            | sort | uniq \
            | sed 's/|/ -> /g' \
            >> "$SUMMARY_LOG"
        echo "" >> "$SUMMARY_LOG"
    fi

    
    echo "For detailed analysis, see the master report file: $MASTER_LOG" >> "$SUMMARY_LOG"
    echo "" >> "$SUMMARY_LOG"
    
    # Print output location information
    echo -e "${GREEN}[+] Scan complete! Results saved to: ${OUTPUT_DIR}/${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Summary report: ${SUMMARY_LOG}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Detailed report: ${MASTER_LOG}${NC}" | tee -a "$CONSOLE_LOG"
    
        # Create a formatted vulnerability target list if any vulnerabilities found
    if [ $total_vuln_count -gt 0 ]; then
        TARGET_LIST="${OUTPUT_DIR}/high_value_targets.txt"
        echo "# High-Value Exploitation Targets" > "$TARGET_LIST"
        echo "# ===============================" >> "$TARGET_LIST"
        echo "# These targets have been identified as high-value for dylib hijacking" >> "$TARGET_LIST"
        echo "" >> "$TARGET_LIST"
        
        if [ $weak_vuln_count -gt 0 ]; then
            echo "## Weak Dylib Targets" >> "$TARGET_LIST"
            grep -v "^#" "$WEAK_DYLIBS_LOG" \
                | sort -u \
                | awk -F'|' '{printf "%-60s => %s\n", $1, $2}' \
                >> "$TARGET_LIST"
            echo "" >> "$TARGET_LIST"
        fi
        
        if [ $rpath_vuln_count -gt 0 ]; then
            echo "## RPATH Hijacking Targets" >> "$TARGET_LIST"
            grep -v "^#" "$RPATH_LOG" \
                | sort -u \
                | awk -F'|' '{printf "%-60s => %s\n", $1, $2}' \
                >> "$TARGET_LIST"
            echo "" >> "$TARGET_LIST"
        fi
        
        if [ $envvar_vuln_count -gt 0 ]; then
            echo "## Environment Variable Hijacking Targets" >> "$TARGET_LIST"
            grep -v "^#" "$ENV_VAR_LOG" \
                | sort -u \
                | awk -F'|' '{printf "%-60s => %s\n", $1, $2}' \
                >> "$TARGET_LIST"
            echo "" >> "$TARGET_LIST"
            
            # Generate quick exploitation commands
            EXPLOITS_FILE="${OUTPUT_DIR}/exploitation_commands.txt"
            echo "# Quick Exploitation Commands for Environment Variable Hijacking" > "$EXPLOITS_FILE"
            echo "# =======================================================" >> "$EXPLOITS_FILE"
            echo "# Use these commands to test DYLD_INSERT_LIBRARIES hijacking with the basic_injection.dylib template" >> "$EXPLOITS_FILE"
            echo "" >> "$EXPLOITS_FILE"
            
            grep -v "^#" "$ENV_VAR_LOG" \
                | sort -u \
                | awk -F'|' '{printf "DYLD_INSERT_LIBRARIES=/path/to/malicious.dylib %s\n", $1}' \
                >> "$EXPLOITS_FILE"
            
            echo -e "${GREEN}[+] Exploitation commands: ${EXPLOITS_FILE}${NC}" | tee -a "$CONSOLE_LOG"
        fi
        
        echo -e "${GREEN}[+] High-value targets list: ${TARGET_LIST}${NC}" | tee -a "$CONSOLE_LOG"
    fi

    # Cleanup
    rm -rf "$TEMP_DIR"
}


# Run the main function
main