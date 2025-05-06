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

# Create temporary directory for results
TEMP_DIR=$(mktemp -d)
RESULTS_FILE="${TEMP_DIR}/scan_results.txt"
WEAK_DYLIBS_FILE="${TEMP_DIR}/weak_dylibs.txt"
RPATH_DEPS_FILE="${TEMP_DIR}/rpath_deps.txt"
VULNERABLE_FILE="${TEMP_DIR}/vulnerable_targets.txt"

# Function to find all Mach-O binaries in a directory
find_macho_files() {
    echo -e "${GREEN}[+] Finding Mach-O files in ${SCAN_DIR}...${NC}"
    find "$SCAN_DIR" -type f -not -path "*/\.*" -exec file {} \; | grep "Mach-O" | cut -d':' -f1
}

# Function to check if a binary has LC_LOAD_WEAK_DYLIB commands
check_weak_dylibs() {
    local binary="$1"
    local binary_name=$(basename "$binary")
    
    echo -e "${GREEN}[+] Checking for weak dylibs in ${binary_name}${NC}"
    
    # Get all LC_LOAD_WEAK_DYLIB references
    otool -l "$binary" 2>/dev/null | grep -A 3 "LC_LOAD_WEAK_DYLIB" | grep "name" | awk '{print $2}' > "${TEMP_DIR}/${binary_name}_weak.txt"
    
    if [ -s "${TEMP_DIR}/${binary_name}_weak.txt" ]; then
        echo "Binary: $binary" >> "$WEAK_DYLIBS_FILE"
        echo "Weak Dylibs:" >> "$WEAK_DYLIBS_FILE"
        
        while read -r lib; do
            # Check if library exists
            if [ ! -f "$lib" ] && [[ ! "$lib" == @* ]]; then
                echo -e "${RED}    [-] ${lib} (DOES NOT EXIST - POTENTIAL HIJACK TARGET)${NC}"
                echo "  - $lib (DOES NOT EXIST - POTENTIAL HIJACK TARGET)" >> "$WEAK_DYLIBS_FILE"
                echo "$binary|$lib|weak_dylib" >> "$VULNERABLE_FILE"
            else
                echo -e "    ${lib}"
                echo "  - $lib" >> "$WEAK_DYLIBS_FILE"
            fi
        done < "${TEMP_DIR}/${binary_name}_weak.txt"
        echo "" >> "$WEAK_DYLIBS_FILE"
    fi
    
    rm "${TEMP_DIR}/${binary_name}_weak.txt" 2>/dev/null
}

# Function to check for @rpath dependencies
check_rpath_deps() {
    local binary="$1"
    local binary_name=$(basename "$binary")
    
    echo -e "${GREEN}[+] Checking for @rpath dependencies in ${binary_name}${NC}"
    
    # Get all @rpath references
    otool -l "$binary" 2>/dev/null | grep -A 3 "LC_LOAD_DYLIB" | grep "name" | grep "@rpath" | awk '{print $2}' > "${TEMP_DIR}/${binary_name}_rpath.txt"
    
    if [ -s "${TEMP_DIR}/${binary_name}_rpath.txt" ]; then
        echo "Binary: $binary" >> "$RPATH_DEPS_FILE"
        echo "RPATH Dependencies:" >> "$RPATH_DEPS_FILE"
        
        while read -r lib; do
            echo "  - $lib" >> "$RPATH_DEPS_FILE"
        done < "${TEMP_DIR}/${binary_name}_rpath.txt"
        
        # Get LC_RPATH commands
        echo "RPATH Search Paths:" >> "$RPATH_DEPS_FILE"
        rpaths=$(otool -l "$binary" 2>/dev/null | grep -A 2 "LC_RPATH" | grep "path" | awk '{print $2}')
        
        if [ ! -z "$rpaths" ]; then
            local is_first=true
            local first_rpath=""
            local dylib_found=false
            
            echo -e "${YELLOW}[!] RPATH search order:${NC}"
            
            for rpath in $rpaths; do
                # Resolve @loader_path or @executable_path if possible
                local resolved_path=""
                if [[ "$rpath" == @loader_path* ]]; then
                    bin_dir=$(dirname "$binary")
                    resolved_path="${rpath/@loader_path/$bin_dir}"
                    echo -e "    ${rpath} -> ${resolved_path}"
                    echo "  - ${rpath} -> ${resolved_path}" >> "$RPATH_DEPS_FILE"
                elif [[ "$rpath" == @executable_path* ]]; then
                    app_dir=$(dirname "$binary")
                    resolved_path="${rpath/@executable_path/$app_dir}"
                    echo -e "    ${rpath} -> ${resolved_path}"
                    echo "  - ${rpath} -> ${resolved_path}" >> "$RPATH_DEPS_FILE"
                else
                    echo -e "    ${rpath}"
                    echo "  - ${rpath}" >> "$RPATH_DEPS_FILE"
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
                            echo -e "    Found ${dylib_name} at ${full_path}"
                            echo "  - Found ${dylib_name} at ${full_path}" >> "$RPATH_DEPS_FILE"
                        fi
                    fi
                done < "${TEMP_DIR}/${binary_name}_rpath.txt"
            done
            
            # Check for potential hijacking via rpath ordering
            if ! $dylib_found && [ ! -z "$first_rpath" ]; then
                echo -e "${RED}    [!] Potential RPATH hijacking: First search path doesn't contain required dylibs${NC}"
                echo "  - VULNERABLE: First search path doesn't contain required dylibs" >> "$RPATH_DEPS_FILE"
                
                while read -r dylib; do
                    dylib_name=${dylib/@rpath\//}
                    echo "$binary|$first_rpath/$dylib_name|rpath_ordering" >> "$VULNERABLE_FILE"
                done < "${TEMP_DIR}/${binary_name}_rpath.txt"
            fi
        else
            echo -e "    No LC_RPATH commands found"
            echo "  - No LC_RPATH commands found" >> "$RPATH_DEPS_FILE"
        fi
        
        echo "" >> "$RPATH_DEPS_FILE"
    fi
    
    rm "${TEMP_DIR}/${binary_name}_rpath.txt" 2>/dev/null
}

# Function to check code signing restrictions
check_code_signing() {
    local binary="$1"
    local binary_name=$(basename "$binary")
    
    echo -e "${GREEN}[+] Checking code signing for ${binary_name}${NC}"
    
    # Check code signing
    local cs_info=$(codesign -dv "$binary" 2>&1)
    local has_hardened_runtime=false
    local has_library_validation=false
    local has_disable_lib_validation=false
    
    if echo "$cs_info" | grep -q "runtime"; then
        echo -e "${RED}    [-] Has hardened runtime${NC}"
        has_hardened_runtime=true
    fi
    
    if echo "$cs_info" | grep -q "library-validation"; then
        echo -e "${RED}    [-] Has library validation${NC}"
        has_library_validation=true
    else
        echo -e "${YELLOW}    [!] No library validation - potential target${NC}"
    fi
    
    # Check entitlements
    local entitlements=$(codesign -dv --entitlements - "$binary" 2>&1)
    if echo "$entitlements" | grep -q "disable-library-validation"; then
        echo -e "${YELLOW}    [!] Has disable-library-validation entitlement - potential target${NC}"
        has_disable_lib_validation=true
    fi
    
    # Update vulnerable file for code signing status
    if grep -q "$binary" "$VULNERABLE_FILE"; then
        if $has_hardened_runtime && $has_library_validation && ! $has_disable_lib_validation; then
            # Mark as likely protected
            sed -i '' "s|$binary|$binary (PROTECTED - code signing restrictions)|g" "$VULNERABLE_FILE"
        fi
    fi
}

# Main function
main() {
    echo -e "${GREEN}[+] Starting scan...${NC}"
    echo "Scan started at: $(date)" > "$RESULTS_FILE"
    echo "Target directory: $SCAN_DIR" >> "$RESULTS_FILE"
    echo "=============================" >> "$RESULTS_FILE"
    
    # Create header for vulnerable targets file
    echo "# Potentially vulnerable targets for dylib hijacking" > "$VULNERABLE_FILE"
    echo "# Format: binary_path|dylib_path|vulnerability_type" >> "$VULNERABLE_FILE"
    
    # Get list of Mach-O binaries
    local macho_files=$(find_macho_files)
    
    if [ -z "$macho_files" ]; then
        echo -e "${RED}[-] No Mach-O files found in ${SCAN_DIR}${NC}"
        echo "No Mach-O files found." >> "$RESULTS_FILE"
        exit 1
    fi
    
    echo -e "${GREEN}[+] Found $(echo "$macho_files" | wc -l | xargs) Mach-O binaries${NC}"
    echo "Found $(echo "$macho_files" | wc -l | xargs) Mach-O binaries" >> "$RESULTS_FILE"
    
    # Process each binary
    for binary in $macho_files; do
        echo "==============================================================="
        echo -e "${BLUE}Analyzing: ${binary}${NC}"
        
        # Add to results file
        echo "" >> "$RESULTS_FILE"
        echo "Analyzing: $binary" >> "$RESULTS_FILE"
        
        check_weak_dylibs "$binary"
        check_rpath_deps "$binary"
        check_code_signing "$binary"
    done
    
    # Print summary
    echo "==============================================================="
    echo -e "${BLUE}Scan Complete - Summary${NC}"
    
    VULN_COUNT=$(grep -v "^#" "$VULNERABLE_FILE" | grep -v "PROTECTED" | wc -l | xargs)
    WEAK_COUNT=$(grep -c "weak_dylib" "$VULNERABLE_FILE")
    RPATH_COUNT=$(grep -c "rpath_ordering" "$VULNERABLE_FILE")
    
    echo -e "${GREEN}[+] Total potentially vulnerable binaries: ${VULN_COUNT}${NC}"
    echo -e "${GREEN}[+] Weak dylib vulnerabilities: ${WEAK_COUNT}${NC}"
    echo -e "${GREEN}[+] RPATH ordering vulnerabilities: ${RPATH_COUNT}${NC}"
    
    echo "" >> "$RESULTS_FILE"
    echo "Scan Summary:" >> "$RESULTS_FILE"
    echo "Total potentially vulnerable binaries: $VULN_COUNT" >> "$RESULTS_FILE"
    echo "Weak dylib vulnerabilities: $WEAK_COUNT" >> "$RESULTS_FILE"
    echo "RPATH ordering vulnerabilities: $RPATH_COUNT" >> "$RESULTS_FILE"
    
    # Save results
    if [ $VULN_COUNT -gt 0 ]; then
        RESULTS_OUTPUT="dylib_scan_results_$(date +%Y%m%d_%H%M%S).txt"
        cat "$RESULTS_FILE" > "$RESULTS_OUTPUT"
        echo "" >> "$RESULTS_OUTPUT"
        echo "Detailed vulnerability information:" >> "$RESULTS_OUTPUT"
        cat "$VULNERABLE_FILE" | grep -v "^#" >> "$RESULTS_OUTPUT"
        
        echo -e "${GREEN}[+] Detailed results saved to ${RESULTS_OUTPUT}${NC}"
    fi
    
    # Cleanup
    rm -rf "$TEMP_DIR"
}

# Run the main function
main "$binary")
                    while [[ ! "$app_dir" == *".app"* && "$app_dir" != "/" ]]; do
                        app_dir=$(dirname "$app_dir")
                    done
                    if [[ "$app_dir" == "/" ]]; then
                        app_dir=$(dirname