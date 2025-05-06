#!/bin/bash
#
# Dylib Hijacking Toolkit - Compilation Script
#
# This script automatically compiles all C tools in the toolkit
# and ensures all necessary directories are created.
#

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}   Dylib Hijacking Toolkit - Compilation Tool    ${NC}"
echo -e "${BLUE}=================================================${NC}"

# Check for Xcode command line tools
if ! command -v gcc &> /dev/null; then
    echo -e "${RED}[!] GCC not found. Please install Xcode Command Line Tools:${NC}"
    echo -e "${YELLOW}    xcode-select --install${NC}"
    exit 1
fi

# Create necessary directories if they don't exist
mkdir -p bin
mkdir -p build

# Compile AMFI Flags Checker
echo -e "${GREEN}[+] Compiling AMFI Flags Checker...${NC}"
gcc -o bin/amfi_checker tools/amfi_checker.c -framework Security
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Successfully compiled amfi_checker to bin/amfi_checker${NC}"
else
    echo -e "${RED}[-] Failed to compile amfi_checker${NC}"
fi

# Compile Basic Dylib Template
echo -e "${GREEN}[+] Compiling Basic Dylib Template...${NC}"
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation templates/basic_dylib_template.c -o build/basic_injection.dylib
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[+] Successfully compiled basic injection dylib to build/basic_injection.dylib${NC}"
else
    echo -e "${RED}[-] Failed to compile basic injection dylib${NC}"
fi

# Compile Keylogger Template (only compiled if explicitly chosen)
echo -e "${YELLOW}[!] The keylogger template requires additional frameworks. Compile it? [y/n]${NC}"
read -r compile_keylogger

if [[ "$compile_keylogger" == "y" || "$compile_keylogger" == "Y" ]]; then
    echo -e "${GREEN}[+] Compiling Keylogger Dylib Template...${NC}"
    gcc -dynamiclib -framework Cocoa -framework Carbon templates/keylogger_dylib.c -o build/keylogger.dylib
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Successfully compiled keylogger dylib to build/keylogger.dylib${NC}"
    else
        echo -e "${RED}[-] Failed to compile keylogger dylib${NC}"
    fi
else
    echo -e "${YELLOW}[!] Skipping keylogger compilation${NC}"
fi

# Create an example dylib hijacking library for demonstration
echo -e "${GREEN}[+] Creating example dylib hijacking template...${NC}"

# First create a simple original dylib
echo -e "${GREEN}[+] Creating original dylib for hijacking demonstration...${NC}"
cat > build/temp_original.c << EOF
#include <stdio.h>

void original_function() {
    printf("Original function called\n");
}

int calculate_sum(int a, int b) {
    return a + b;
}
EOF

gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 build/temp_original.c -o build/liboriginal.dylib
if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Failed to compile original dylib${NC}"
    rm build/temp_original.c
else
    echo -e "${GREEN}[+] Successfully compiled original dylib to build/liboriginal.dylib${NC}"
    
    # Now compile the hijacking dylib that re-exports it
    gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation templates/dylib_hijacking_template.c -Wl,-reexport_library,build/liboriginal.dylib -o build/hijack_example.dylib
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Successfully compiled hijacking example to build/hijack_example.dylib${NC}"
        # Fix the path reference
        install_name_tool -change @rpath/original.dylib $(pwd)/build/liboriginal.dylib build/hijack_example.dylib
        echo -e "${GREEN}[+] Fixed path reference in hijack_example.dylib${NC}"
    else
        echo -e "${RED}[-] Failed to compile hijacking example${NC}"
    fi
    
    # Clean up temporary file
    rm build/temp_original.c
fi

# Make all scripts executable
echo -e "${GREEN}[+] Making all scripts executable...${NC}"
chmod +x tools/*.sh

echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}[+] Compilation complete!${NC}"
echo -e "${YELLOW}[!] You can find the compiled tools in:${NC}"
echo -e "    ${YELLOW}bin/ - Executable tools${NC}"
echo -e "    ${YELLOW}build/ - Compiled dylibs${NC}"
echo -e "${BLUE}=================================================${NC}"

# Provide tips for testing
echo -e "${GREEN}[+] Quick test commands:${NC}"
echo -e "    ${YELLOW}./bin/amfi_checker /Applications/Safari.app/Contents/MacOS/Safari${NC}"
echo -e "    ${YELLOW}./tools/dylib_finder.sh /Applications${NC}"
echo -e "    ${YELLOW}DYLD_INSERT_LIBRARIES=$(pwd)/build/basic_injection.dylib /bin/ls${NC}"
echo -e "${BLUE}=================================================${NC}"

exit 0