/**
 * AMFI Flags Checker Tool
 * 
 * This tool checks the AppleMobileFileIntegrity (AMFI) flags for a given binary
 * and determines what restrictions are applied by AMFI to the process.
 * 
 * Compilation:
 * gcc -o amfi_checker amfi_checker.c -framework Security
 * 
 * Usage:
 * ./amfi_checker <path-to-binary>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/stat.h>

// AMFI output flags definitions
#define AMFI_DYLD_OUTPUT_ALLOW_AT_PATH                  (1 << 0)
#define AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS                (1 << 1)
#define AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE      (1 << 2)
#define AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS           (1 << 3)
#define AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS               (1 << 4)
#define AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION (1 << 5)
#define AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING      (1 << 6)
#define AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS            (1 << 7)

// AMFI input flags
#define AMFI_DYLD_INPUT_PROC_HAS_RESTRICT_SEG           (1 << 0)
#define AMFI_DYLD_INPUT_PROC_IS_ENCRYPTED               (1 << 1)

// CS Flags
#define CS_VALID                    0x00000001
#define CS_ADHOC                    0x00000002
#define CS_GET_TASK_ALLOW           0x00000004
#define CS_INSTALLER                0x00000008
#define CS_FORCED_LV                0x00000010
#define CS_INVALID_ALLOWED          0x00000020
#define CS_HARD                     0x00000100
#define CS_KILL                     0x00000200
#define CS_CHECK_EXPIRATION         0x00000400
#define CS_RESTRICT                 0x00000800
#define CS_ENFORCEMENT              0x00001000
#define CS_REQUIRE_LV               0x00002000
#define CS_ENTITLEMENTS_VALIDATED   0x00004000
#define CS_NVRAM_UNRESTRICTED       0x00008000
#define CS_RUNTIME                  0x00010000
#define CS_PLATFORM_BINARY          0x04000000

// Prototype for the AMFI check function
typedef int (*amfi_check_dyld_policy_self_t)(uint64_t inFlags, uint64_t* outFlags);

/**
 * Check if a file has a __RESTRICT segment
 * This is done by running otool and parsing the output
 */
int has_restrict_segment(const char* path) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "/usr/bin/otool -l \"%s\" | grep -A 2 __RESTRICT >/dev/null 2>&1", path);
    return system(cmd) == 0;
}

/**
 * Get code signing flags for a binary
 * This is done by running codesign and parsing the output
 */
void get_code_signing_info(const char* path, int* has_hardened_runtime, int* has_library_validation) {
    char cmd[1024];
    FILE* fp;
    char buffer[1024];
    
    *has_hardened_runtime = 0;
    *has_library_validation = 0;
    
    snprintf(cmd, sizeof(cmd), "/usr/bin/codesign -dv \"%s\" 2>&1", path);
    fp = popen(cmd, "r");
    
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "runtime")) {
                *has_hardened_runtime = 1;
            }
            if (strstr(buffer, "library-validation")) {
                *has_library_validation = 1;
            }
        }
        pclose(fp);
    }
}

/**
 * Check if a binary has com.apple.security.cs.disable-library-validation entitlement
 */
int has_disable_library_validation(const char* path) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "/usr/bin/codesign -dv --entitlements - \"%s\" 2>&1 | grep -q 'disable-library-validation'", path);
    return system(cmd) == 0;
}

/**
 * Get csops flags for a running process
 * This is for educational purposes only as we can't easily get this for a binary
 * without running it
 */
void print_csops_example() {
    printf("\nExample command to check CS flags for a running process:\n");
    printf("  csops -status <pid>\n\n");
    printf("Example output might show flags like CS_VALID, CS_RUNTIME, CS_RESTRICT\n");
}

/**
 * Print flag information
 */
void check_flag(uint64_t flags, uint64_t flag, const char* description) {
    if (flags & flag) {
        printf("  [+] %-45s: \033[32mALLOWED\033[0m\n", description);
    } else {
        printf("  [-] %-45s: \033[31mRESTRICTED\033[0m\n", description);
    }
}

/**
 * Main function
 */
int main(int argc, char *argv[]) {
    // Check arguments
    if (argc != 2) {
        printf("Usage: %s <path-to-binary>\n", argv[0]);
        return 1;
    }
    
    const char* binary_path = argv[1];
    
    // Check if file exists
    struct stat st;
    if (stat(binary_path, &st) != 0) {
        printf("[-] Binary %s does not exist\n", binary_path);
        return 1;
    }
    
    printf("\n\033[1;34m===============================================\033[0m\n");
    printf("\033[1;34m     AMFI Restrictions Analysis Tool\033[0m\n");
    printf("\033[1;34m===============================================\033[0m\n\n");
    
    printf("[*] Analyzing AMFI restrictions for: %s\n\n", binary_path);
    
    // Check for __RESTRICT segment
    int has_restrict = has_restrict_segment(binary_path);
    printf("[*] Binary characteristics:\n");
    printf("  %s __RESTRICT segment\n", has_restrict ? "Has" : "No");
    
    // Check code signing flags
    int has_hardened_runtime = 0;
    int has_library_validation = 0;
    get_code_signing_info(binary_path, &has_hardened_runtime, &has_library_validation);
    
    printf("  %s hardened runtime (CS_RUNTIME)\n", has_hardened_runtime ? "Has" : "No");
    printf("  %s library validation\n", has_library_validation ? "Has" : "No");
    
    int has_disable_lib_val = has_disable_library_validation(binary_path);
    if (has_disable_lib_val) {
        printf("  Has disable-library-validation entitlement\n");
    }
    
    // Set up AMFI input flags
    uint64_t inFlags = 0;
    if (has_restrict) {
        inFlags |= AMFI_DYLD_INPUT_PROC_HAS_RESTRICT_SEG;
    }
    
    // Try to get AMFI flags
    printf("\n[*] Attempting to query AMFI for dyld policy flags...\n");
    
    // Load libSystem to access the function
    void* libSystem = dlopen("/usr/lib/libSystem.dylib", RTLD_LAZY);
    if (!libSystem) {
        printf("[-] Failed to load libSystem: %s\n", dlerror());
        return 1;
    }
    
    // Get the amfi_check_dyld_policy_self function
    amfi_check_dyld_policy_self_t amfi_check = (amfi_check_dyld_policy_self_t)dlsym(libSystem, "amfi_check_dyld_policy_self");
    if (!amfi_check) {
        printf("[-] Failed to get amfi_check_dyld_policy_self: %s\n", dlerror());
        dlclose(libSystem);
        return 1;
    }
    
    uint64_t outFlags = 0;
    int result = amfi_check(inFlags, &outFlags);
    
    printf("\n[*] AMFI flags result: 0x%llx (return code: %d)\n\n", outFlags, result);
    
    // Check each flag
    printf("[*] Detailed AMFI restrictions analysis:\n");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_AT_PATH, "Allow @paths");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS, "Allow path environment variables");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE, "Allow custom shared cache");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS, "Allow fallback paths");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS, "Allow print environment variables");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION, "Allow failed library insertion");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING, "Allow library interposing");
    check_flag(outFlags, AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS, "Allow embedded variables");
    
    // Check for environment variable injection possibility
    int env_vars_allowed = (outFlags & (AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS | 
                                       AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS | 
                                       AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE)) != 0;
    
    printf("\n[*] Environment variables injection: %s\n", 
        env_vars_allowed ? "\033[32mPOSSIBLE\033[0m" : "\033[31mRESTRICTED\033[0m");
    
    if (env_vars_allowed) {
        printf("\n[*] Injection command example:\n");
        printf("  DYLD_INSERT_LIBRARIES=/path/to/malicious.dylib %s\n", binary_path);
    } else {
        printf("\n[*] This binary is restricted from using DYLD_* environment variables.\n");
        printf("    Consider other injection techniques like dylib hijacking.\n");
    }
    
    // Print example csops command
    print_csops_example();
    
    printf("\n\033[1;34m===============================================\033[0m\n");
    
    dlclose(libSystem);
    return 0;
}