// vulnerable_client.c - Test vulnerability detection
// WARNING: Contains intentional security vulnerabilities for testing purposes
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// VULN 1: Buffer overflow via strcpy
void process_username(char *input) {
    char username[32];
    strcpy(username, input);  // No bounds checking
    printf("Username: %s\n", username);
}

// VULN 2: Format string vulnerability
void log_message(char *msg) {
    printf(msg);  // User-controlled format string
}

// VULN 3: Integer overflow in size calculation
char* allocate_buffer(int count, int size) {
    int total = count * size;  // May overflow
    return (char*)malloc(total);
}

// VULN 4: Use of dangerous gets()
void read_input() {
    char buffer[128];
    gets(buffer);  // Deprecated and dangerous
    printf("Input: %s\n", buffer);
}

// VULN 5: Unvalidated sprintf
void format_data(char *name, int value) {
    char output[64];
    sprintf(output, "%s: %d", name, value);  // Should use snprintf
    printf("%s\n", output);
}

// Safe function for comparison
void safe_process(const char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Safe: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    process_username(argv[1]);
    log_message("Test message\n");

    char *buf = allocate_buffer(100, 1024);
    if (buf) {
        free(buf);
    }

    format_data("Value", 42);
    safe_process("Safe input");

    return 0;
}
