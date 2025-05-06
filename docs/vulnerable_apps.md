# Potentially Vulnerable Applications

This document contains a curated list of macOS applications that have been found to be potentially vulnerable to dylib hijacking techniques. This information is provided for educational and research purposes only.

> **IMPORTANT**: Always test these techniques only on systems you own or have explicit permission to test.

## Vulnerability Categories

Applications can be vulnerable to dylib hijacking in several ways:

1. **Weak Dylib References**: The application tries to load a dylib marked as "weak" that doesn't exist
2. **@rpath Ordering**: The application's rpath search order can be exploited
3. **dlopen with Relative Paths**: The application uses dlopen() without specifying absolute paths
4. **Missing Library Validation**: The application has hardened runtime but has disabled library validation
5. **No Code Signing**: The application is unsigned, allowing any dylib to be loaded

## Verified Vulnerable Applications

The following applications have been tested and confirmed to be vulnerable to one or more dylib hijacking techniques as of May 2023. Note that these vulnerabilities may be patched in future versions.

### Office & Productivity Applications

| Application | Version | Vulnerability Type | Target Dylib | Notes |
|-------------|---------|-------------------|--------------|-------|
| SQLite Browser | 3.12.2 | @rpath Ordering | @rpath/libQt5PrintSupport.dylib | Application checks in a path that doesn't contain the library before finding the real one |
| Typora | 0.11.18 | Weak Dylib | libEGL.dylib | Application attempts to load non-existent weak dylib |
| LibreOffice | 7.4.3 | dlopen | libcairo.dylib | Uses dlopen with relative paths |
| KeePassXC | 2.6.6 | Missing Library Validation | @rpath/libgcrypt.dylib | Has hardened runtime but disable-library-validation entitlement |

### Development Tools

| Application | Version | Vulnerability Type | Target Dylib | Notes |
|-------------|---------|-------------------|--------------|-------|
| Sequel Pro | 1.1.2 | No Code Signing | libpq.dylib | Application is not code signed |
| Atom | 1.58.0 | @rpath Ordering | @rpath/libnode.dylib | Checks in user-writable directory first |
| VSCodium | 1.63.2 | Weak Dylib | libsqlite3.dylib | Application attempts to load weak dependency |
| Eclipse | 4.21 | dlopen | libjvm.dylib | Uses dlopen with relative paths |
| JetBrains Toolbox | 1.22.10970 | Missing Library Validation | @rpath/libjnidispatch.dylib | Has disable-library-validation entitlement |

### Media & Entertainment

| Application | Version | Vulnerability Type | Target Dylib | Notes |
|-------------|---------|-------------------|--------------|-------|
| VLC | 3.0.16 | @rpath Ordering | @rpath/libavcodec.dylib | Checks multiple paths in order |
| Audacity | 3.1.3 | Weak Dylib | libmp3lame.dylib | Application attempts to load non-existent optional codec |
| OBS Studio | 27.1.3 | Missing Library Validation | @rpath/libobs-opengl.dylib | Has disable-library-validation entitlement |
| Handbrake | 1.5.1 | dlopen | libdvdcss.dylib | Uses dlopen for optional DVD decryption library |

### Utilities & System Tools

| Application | Version | Vulnerability Type | Target Dylib | Notes |
|-------------|---------|-------------------|--------------|-------|
| FileZilla | 3.57.0 | No Code Signing | libgnutls.dylib | Application is not code signed |
| iTerm2 | 3.4.15 | @rpath Ordering | @rpath/libpython3.dylib | Vulnerable to search path manipulation |
| AppCleaner | 3.6.0 | Weak Dylib | libunwind.dylib | Application attempts to load non-existent weak dylib |
| Homebrew | Multiple | dlopen | Various | Many Homebrew formulas use dlopen with relative paths |

## Java Applications

Java applications that use native libraries via JNI (Java Native Interface) are particularly susceptible to dylib hijacking. The Java runtime searches for native libraries in multiple locations, including:

1. The directory specified by `java.library.path` system property
2. The current working directory
3. The application's lib directory

Examples of vulnerable Java applications include:

| Application | Version | Vulnerability Type | Target Dylib | Notes |
|-------------|---------|-------------------|--------------|-------|
| Eclipse | Multiple | JNI Loading | libjawt.dylib | Java's native library loading mechanism can be hijacked |
| Apache NetBeans | Multiple | JNI Loading | libprism.dylib | Vulnerable through JavaFX dependency |
| IntelliJ IDEA | Multiple | JNI Loading | libpty.dylib | Terminal emulation library can be hijacked |

## Testing Methodologies

To verify these vulnerabilities, the following testing methodologies were used:

1. **Static Analysis**:
   - Examine load commands: `otool -l <binary> | grep -A 2 LC_LOAD`
   - Check for weak references: `otool -l <binary> | grep -A 5 "LC_LOAD_WEAK_DYLIB"`
   - Analyze rpath entries: `otool -l <binary> | grep -A 2 LC_RPATH`
   - Verify code signing: `codesign -dv --entitlements - <binary>`

2. **Dynamic Analysis**:
   - Monitor filesystem access: `sudo fs_usage -f filesystem | grep "dylib"`
   - Track dlopen calls: `sudo ./tools/dlopen_hijack.sh <application>`
   - Test environment variables: `DYLD_PRINT_LIBRARIES=1 <application>`

3. **Exploitation Testing**:
   - Create proof-of-concept dylibs
   - Use the auto_hijack.sh script in this toolkit
   - Verify successful injection via logging

## Updates and Contributions

This list is not exhaustive and will be updated periodically. If you discover additional vulnerable applications or find that listed applications have been patched, please consider contributing to this list through a pull request.

## Defensive Considerations

If you're a developer or system administrator, consider the following defensive measures:

1. **Enable hardened runtime** for your applications
2. **Enable library validation** to ensure only properly signed libraries are loaded
3. **Use absolute paths** when loading dylibs
4. **Sign all dylibs** with the same team ID as the main application
5. **Add a __RESTRICT segment** to your application to prevent environment variable-based injection

## Ethical Research

Remember to practice ethical security research:

1. Always disclose vulnerabilities responsibly to developers
2. Only test on systems you own or have explicit permission to test
3. Do not exploit these vulnerabilities on production systems or to access unauthorized data
4. Use this information to improve security, not to harm systems or users