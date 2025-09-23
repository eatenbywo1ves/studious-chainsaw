#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "../include/tmux.h"

static FILE *log_file = NULL;

static void init_logging(void) {
    if (!log_file) {
        log_file = fopen("/tmp/tmux-clone.log", "a");
        if (!log_file) {
            log_file = stderr;
        }
    }
}

void log_info(const char *format, ...) {
    init_logging();
    
    time_t now;
    time(&now);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline
    
    fprintf(log_file, "[%s] INFO: ", time_str);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
}

void log_error(const char *format, ...) {
    init_logging();
    
    time_t now;
    time(&now);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline
    
    fprintf(log_file, "[%s] ERROR: ", time_str);
    
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    
    fprintf(log_file, "\n");
    fflush(log_file);
}