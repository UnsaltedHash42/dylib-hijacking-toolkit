#!/bin/bash
#
# Dylib Hijacking Scanner
#
# This script scans applications for potential dylib hijacking vulnerabilities
# It identifies:
# 1. Binaries with LC_LOAD_WEAK_DYLIB that could be hijacked
# 2. Binaries with @rpath dependencies where search order can be exploited
# 3. Code signing restrictions that may prevent exploitation
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
EXECUTABLE_LIST="${OUTPUT_DIR}/scanned_executables.txt"
CONSOLE_LOG="${OUTPUT_DIR}/console_output.txt"

# Create temporary directory for results
TEMP_DIR=$(mktemp -d)

# Function to find all Mach-O binaries in a directory
find_macho_files() {
    echo -e "${GREEN}[+] Finding Mach-O files in ${SCAN_DIR}...${NC}" | tee -a "$CONSOLE_LOG"
    
    # Create a file to store the list of binaries
    MACHO_LIST="${TEMP_DIR}/macho_list.txt"
    
    # Use find to locate Mach-O binaries and store them in the file
    find "$SCAN_DIR" -type f -not -path "*/\.*" -exec file {} \; | grep "Mach-O" | cut -d':' -f1 > "$MACHO_LIST"
    
    # Return the file path containing the list
    echo "$MACHO_LIST"
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
    
    echo "$vulnerable"
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
    
    echo "$vulnerable"
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
        
        return "true"
    fi
    
    # Check entitlements
    local entitlements=$(codesign -dv --entitlements - "$binary" 2>&1)
    if echo "$entitlements" | grep -q "disable-library-validation"; then
        echo -e "${YELLOW}    [!] Has disable-library-validation entitlement - potential target${NC}" | tee -a "$CONSOLE_LOG"
        echo "  - VULNERABLE: Has disable-library-validation entitlement" >> "$MASTER_LOG"
        
        # Add to library validation vulnerability log
        echo "$binary|DISABLED_LIBRARY_VALIDATION" >> "$LIBRARY_VALIDATION_LOG"
        
        has_disable_lib_validation=true
        return "true"
    fi
    
    echo "false"
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
    
    echo "# List of All Scanned Executables" > "$EXECUTABLE_LIST"
    echo "" >> "$EXECUTABLE_LIST"
    
    # Get list of Mach-O binaries
    macho_list_file=$(find_macho_files)
    
    if [ ! -s "$macho_list_file" ]; then
        echo -e "${RED}[-] No Mach-O files found in ${SCAN_DIR}${NC}" | tee -a "$CONSOLE_LOG"
        echo "No Mach-O files found." >> "$MASTER_LOG"
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    # Count the number of binaries
    binary_count=$(wc -l < "$macho_list_file" | xargs)
    echo -e "${GREEN}[+] Found ${binary_count} Mach-O binaries${NC}" | tee -a "$CONSOLE_LOG"
    echo "Found ${binary_count} Mach-O binaries" >> "$MASTER_LOG"
    
    # Variables to track vulnerability counts
    weak_vuln_count=0
    rpath_vuln_count=0
    libval_vuln_count=0
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
        weak_vulnerable=$(check_weak_dylibs "$binary")
        rpath_vulnerable=$(check_rpath_deps "$binary")
        libval_vulnerable=$(check_code_signing "$binary")
        
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
        
        if [ "$binary_vulnerable" = "true" ]; then
            total_vuln_count=$((total_vuln_count + 1))
        fi
        
    done < "$macho_list_file"
    
    # Print summary
    echo "===============================================================" | tee -a "$CONSOLE_LOG"
    echo -e "${BLUE}Scan Complete - Summary${NC}" | tee -a "$CONSOLE_LOG"
    
    echo -e "${GREEN}[+] Total analyzed binaries: ${total_binaries}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Total potentially vulnerable binaries: ${total_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Weak dylib vulnerabilities: ${weak_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] RPATH ordering vulnerabilities: ${rpath_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    echo -e "${GREEN}[+] Library validation vulnerabilities: ${libval_vuln_count}${NC}" | tee -a "$CONSOLE_LOG"
    
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
            grep -v "^#" "$WEAK_DYLIBS_LOG" | sort | uniq | awk -F'|' '{printf "%-60s => %s\n", $1, $2}' >> "$TARGET_LIST"
            echo "" >> "$TARGET_LIST"
        fi
        
        if [ $rpath_vuln_count -gt 0 ]; then
            echo "## RPATH Hijacking Targets" >> "$TARGET_LIST"
            grep -v "^#" "$RPATH_LOG" | sort | uniq | awk -F'|' '{printf "%-60s => %s\n", $1, $2}' >> "$TARGET_LIST"
            echo "" >> "$TARGET_LIST"
        fi
        
        echo -e "${GREEN}[+] High-value targets list: ${TARGET_LIST}${NC}" | tee -a "$CONSOLE_LOG"
    fi
    
    # Cleanup
    rm -rf "$TEMP_DIR"
}

# Run the main function
main