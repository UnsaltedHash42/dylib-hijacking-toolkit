# Detailed Notes: Dylib Injection (Apple Silicon)

## 1. Understanding Process Injection

### 1.1 Definition and Significance
- **Process injection** is a technique used to insert code into an existing process, allowing the injected code to run within the context of the target application
- Essential for exploitation on macOS since access control often depends on application signatures and embedded entitlements
- Entitlements determine what actions an application can perform (accessing the camera, files, etc.)
- Some entitlements (especially private Apple ones) are very powerful and can unlock significant privileges

### 1.2 Security Implications
- Running injected code in an application's context allows attackers to obtain rights they didn't have before
- Can bypass security restrictions by inheriting the target application's privileges
- Enables privilege escalation, data exfiltration, and other malicious activities
- Apple implements various protections to limit injection techniques, which we'll explore

## 2. Understanding Dylibs

### 2.1 What is a Dylib?
- Dylib = **Dy**namically linked **lib**rary on macOS (similar to .dll files on Windows)
- File extension is `.dylib`
- Mach-O format binary that contains shared code that can be used by multiple applications
- Loaded at runtime by the dynamic linker/loader (dyld)
- Can contain functions, classes, and resources shared across applications

### 2.2 How Dylibs Work
- Dylibs are loaded by the dyld (dynamic link editor) during application launch
- Applications reference dylibs through load commands embedded in their Mach-O headers
- When a program starts, dyld processes these load commands to locate and load required libraries
- Symbols (functions/variables) from dylibs are resolved and linked to the application at runtime
- This dynamic linking reduces executable size and enables code sharing between applications

### 2.3 Types of Dylib References
- **Direct references**: Hardcoded absolute paths to dylibs
- **@executable_path references**: Relative to the main executable's directory
- **@loader_path references**: Relative to the binary containing the load command
- **@rpath references**: Uses runtime search paths defined by LC_RPATH commands

## 3. DYLD_INSERT_LIBRARIES Injection

### 3.1 Overview
- Environment variable-based injection technique
- Instructs the dyld to load specified dylibs before the main application starts
- Similar to LD_PRELOAD on Linux systems
- When successful, allows arbitrary code execution in the context of the target application
- Has been restricted over time due to security implications

### 3.2 Implementation Details

#### 3.2.1 Basic Implementation
```c
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

#### 3.2.2 Key Components
- **`__attribute__((constructor))`**: GCC-specific attribute that marks a function to be executed when the library is loaded
- The constructor function receives the same arguments as main() (argc and argv)
- `argv[0]` contains the path of the binary being executed
- Using both printf and syslog allows verification through multiple channels

#### 3.2.3 Compilation and Execution
```bash
# Compile the dylib
gcc -dynamiclib example.c -o example.dylib

# Inject into an application
DYLD_INSERT_LIBRARIES=example.dylib ./application
```

### 3.3 Verification Methods

#### 3.3.1 Console Application
- Open Console application (macOS logging system)
- Select the machine under Devices and click Start
- Search for constructor or specific log message
- Execution of injected code will appear in logs

#### 3.3.2 Command Line Logging
```bash
log stream --style syslog --predicate 'eventMessage CONTAINS[c] "constructor"'
```
- Streams logs in real-time
- Filters for messages containing "constructor"
- [c] flag makes the search case-insensitive

### 3.4 Restrictions and Limitations

#### 3.4.1 Overview of Restrictions
Environment variables like DYLD_INSERT_LIBRARIES are ignored when:
1. Main executable has a restricted segment (__RESTRICT,__restrict)
2. SUID/GUID bits are set on the executable
3. Binary has CS_RESTRICT or CS_RUNTIME code signing flags without proper entitlements
4. Program is an entitled binary (typically Apple system binaries)

#### 3.4.2 Adding Restrictions to Binaries
- **Restricted segment**: `gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restricted`
- **SUID/GUID bits**: `sudo chmod +s binary`
- **Code signing flags**: 
  - `codesign -s certificate_name --option=runtime binary` (for CS_RUNTIME)
  - `codesign -s certificate_name --option=library binary` (for library validation)
  - `codesign -s certificate_name --option=0x800 binary` (for CS_RESTRICT)

## 4. Deep Dive into Dyld and AMFI

### 4.1 Dyld Environment Variable Handling

#### 4.1.1 The pruneEnvVars Function
```c
void ProcessConfig::Security::pruneEnvVars(Process& proc)
{
    // For security, setuid programs ignore DYLD_* environment variables.
    // Additionally, the DYLD_* enviroment variables are removed
    // from the environment, so that any child processes doesn't see them.
    //
    // delete all DYLD_* environment variables
    int          removedCount = 0;
    const char** d            = (const char**)proc.envp;
    for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
        if ( strncmp(*s, "DYLD_", 5) != 0 ) {
            *d++ = *s;
        }
        else {
            ++removedCount;
        }
    }
    *d++ = NULL;
    // slide apple parameters
    if ( removedCount > 0 ) {
        proc.apple = d;
        do {
            *d = d[removedCount];
        } while ( *d++ != NULL );
        for ( int i = 0; i < removedCount; ++i )
            *d++ = NULL;
    }
}
```
- Iterates through all environment variables
- Removes any that start with "DYLD_"
- Called conditionally based on security restrictions

#### 4.1.2 Decision Flow for Pruning Variables
- ProcessConfig::Security::Security constructor decides whether to prune
- Decision depends on flags returned by AMFI (AppleMobileFileIntegrity)
- SIP (System Integrity Protection) settings also impact this decision

### 4.2 AMFI Integration

#### 4.2.1 The AMFI System Call
- AMFI = AppleMobileFileIntegrity
- A kernel extension introduced in iOS, added to macOS in 10.10
- Extends the Mandatory Access Control Framework (MACF)
- Enforces SIP and code signing policies
- Called via ___sandbox_ms("AMFI") system call

#### 4.2.2 Key AMFI Output Flags for Dyld
```c
enum amfi_dyld_policy_output_flag_set
{
    AMFI_DYLD_OUTPUT_ALLOW_AT_PATH                  = (1 << 0),
    AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS                = (1 << 1),
    AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE      = (1 << 2),
    AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS           = (1 << 3),
    AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS               = (1 << 4),
    AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION = (1 << 5),
    AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING      = (1 << 6),
    AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS            = (1 << 7),
};
```
- Each flag corresponds to a specific permission
- Particularly important are ALLOW_PATH_VARS and ALLOW_PRINT_VARS for environment variable injection

#### 4.2.3 SIP and AMFI Interactions
- SIP settings (csr_config) influence AMFI's decisions
- CSR_ALLOW_APPLE_INTERNAL bit (0x10) in csr_config affects AMFI behavior
- When SIP is disabled, CSR_ALLOW_APPLE_INTERNAL is set, allowing more flexibility

### 4.3 How AMFI Makes Decisions
AMFI considers multiple factors:
1. If the binary has a __RESTRICT segment
2. If the binary is Fairplay encrypted (App Store)
3. Code signing flags (CS_RESTRICT, CS_RUNTIME)
4. Entitlements (especially library validation entitlements)
5. SIP configuration

## 5. Dylib Hijacking Techniques

### 5.1 Dylib Loading Process

#### 5.1.1 ImageLoader::recursiveLoadLibraries
- Core function responsible for loading required libraries
- Processes load commands to identify dependent libraries
- Resolves rpath variables and locates actual dylib files
- Handles weak dependencies differently than required ones

#### 5.1.2 Key Load Commands
- **LC_LOAD_DYLIB**: Standard command to load a required dylib
- **LC_LOAD_WEAK_DYLIB**: Loads a dylib but continues execution if not found
- **LC_REEXPORT_DYLIB**: Loads a dylib and re-exports its symbols
- **LC_LOAD_UPWARD_DYLIB**: Used for upward dependencies (two libraries depending on each other)
- **LC_RPATH**: Defines runtime search paths for @rpath resolution

### 5.2 Path Variables and Resolution

#### 5.2.1 @executable_path
- Resolves to the directory containing the main executable
- Example: If app is at `/Applications/App.app/Contents/MacOS/App`, then `@executable_path` = `/Applications/App.app/Contents/MacOS`

#### 5.2.2 @loader_path
- Resolves to the directory containing the binary with the load command
- Can be different for each binary in the application bundle

#### 5.2.3 @rpath
- Placeholder resolved using paths from LC_RPATH commands
- Searched in order of appearance until dylib is found
- Enables flexible library locations independent of installation path

### 5.3 Hijacking Scenarios

#### 5.3.1 LC_LOAD_WEAK_DYLIB Exploitation
- Target applications that reference nonexistent dylibs with LC_LOAD_WEAK_DYLIB
- Place malicious dylib at the expected location
- Application loads our dylib without error since it's marked as "weak"

#### 5.3.2 @rpath Ordering Exploitation
- Identify applications with multiple LC_RPATH entries
- Determine which path is searched first
- Place malicious dylib in the first-searched path, even if legitimate dylib exists in later paths

#### 5.3.3 Dylib Proxying ("Re-export" Attack)
- Replace legitimate dylib with malicious one
- Re-export symbols from original dylib to avoid crashes
- Add malicious code via constructor attribute

### 5.4 Finding Vulnerable Applications

#### 5.4.1 Identifying LC_LOAD_WEAK_DYLIB Candidates
```bash
otool -l <binary> | grep -A 5 "LC_LOAD_WEAK_DYLIB"
```
- Check if referenced dylibs exist
- Verify code signing restrictions

#### 5.4.2 Identifying @rpath Candidates
```bash
# Get @rpath dependencies
otool -l <binary> | grep @rpath

# Get LC_RPATH commands
otool -l <binary> | grep -A 2 LC_RPATH
```
- Resolve @rpath variables to actual paths
- Check each path for presence of the dylib
- Determine if search order can be exploited

#### 5.4.3 Verifying Code Signing
```bash
codesign -dv --entitlements - <binary>
```
- Check for hardened runtime flag (prevents most injections)
- Check for library validation flag (requires dylibs to be signed by same team)
- Look for entitlements like com.apple.security.cs.disable-library-validation

### 5.5 Implementing Dylib Hijacking

#### 5.5.1 Basic Implementation
```c
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void custom(int argc, const char **argv)
{
  NSLog(@"Dylib hijack successful in %s", argv[0]);
}
```

#### 5.5.2 Re-exporting Symbols (Proxying)
```bash
# Compile with re-export
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 \
    -framework Foundation hijack.m \
    -Wl,-reexport_library,/path/to/original.dylib \
    -o hijack.dylib

# Fix re-export path if using @rpath
install_name_tool -change @rpath/original.dylib /absolute/path/to/original.dylib hijack.dylib
```

#### 5.5.3 Deployment
- Place dylib in the target location
- Ensure proper permissions
- Original application will load the malicious dylib instead

### 5.6 dlopen Hijacking

#### 5.6.1 dlopen Search Behavior
When dlopen is called with just a filename (no path):
1. $DYLD_LIBRARY_PATH directories (if set and allowed)
2. LC_RPATH directories (from the main executable or calling library)
3. Current working directory (if unrestricted)
4. $DYLD_FALLBACK_LIBRARY_PATH directories (if set and allowed)
5. /usr/local/lib (if unrestricted)
6. /usr/lib

#### 5.6.2 Exploiting dlopen
- Identify applications that use dlopen with relative paths
- Place malicious dylib in a location earlier in the search order
- Use fs_usage to monitor actual search paths:
  ```bash
  sudo fs_usage | grep <library_name>
  ```

## 6. Mitigations and Protections

### 6.1 Preventing DYLD_INSERT_LIBRARIES Attacks
- Use restricted segments: `gcc -sectcreate __RESTRICT __restrict /dev/null file.c -o binary`
- Enable hardened runtime: `codesign -s cert_name --option=runtime binary`
- Enable library validation: `codesign -s cert_name --option=library binary`
- Add CS_RESTRICT flag: `codesign -s cert_name --option=0x800 binary`

### 6.2 Preventing Dylib Hijacking
- Use absolute paths for dylibs instead of @rpath where possible
- Sign applications with hardened runtime
- Enable library validation to enforce team ID matching
- Verify dylib signatures at runtime
- Ensure all referenced dylibs exist in their expected locations

### 6.3 Recommendations for Developers
- Be cautious with LC_LOAD_WEAK_DYLIB
- Properly secure all directories in LC_RPATH search paths
- Sign all dylibs with the same team ID as the main application
- Use library validation when possible
- Avoid using dlopen with relative paths

## 7. Real-World Implications

### 7.1 Security Impact
- Dylib injection can lead to:
  - Privilege escalation
  - Data exfiltration
  - Application manipulation
  - Persistence mechanisms
  
### 7.2 Security Research Applications
- Finding vulnerabilities in high-privilege applications
- Bypassing security restrictions
- Understanding macOS security architecture
- Testing application hardening measures

### 7.3 Legitimate Uses
- Debugging and instrumentation
- Application extensions
- Runtime patching
- Performance monitoring
- Application feature enhancement