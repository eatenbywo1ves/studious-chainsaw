#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include "../include/tmux.h"

#define PERSIST_DIR "/tmp/tmux-clone-sessions"
#define MAX_PATH_LEN 1024

static int ensure_persist_dir(void) {
    struct stat st;
    if (stat(PERSIST_DIR, &st) == -1) {
        if (mkdir(PERSIST_DIR, 0700) == -1) {
            log_error("Failed to create persist directory: %s", strerror(errno));
            return -1;
        }
    }
    return 0;
}

static char* get_session_file_path(const char *session_name) {
    static char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s.session", PERSIST_DIR, session_name);
    return path;
}

int save_session_state(session_t *session) {
    if (!session) return -1;
    
    if (ensure_persist_dir() != 0) {
        return -1;
    }
    
    char *file_path = get_session_file_path(session->name);
    FILE *file = fopen(file_path, "w");
    if (!file) {
        log_error("Failed to open session file for writing: %s", strerror(errno));
        return -1;
    }
    
    fprintf(file, "# tmux-clone session state file\n");
    fprintf(file, "# Session: %s\n", session->name);
    fprintf(file, "# Created: %ld\n", session->created);
    fprintf(file, "# Last attached: %ld\n", session->last_attached);
    fprintf(file, "\n");
    
    fprintf(file, "session_id=%u\n", session->id);
    fprintf(file, "session_name=%s\n", session->name);
    fprintf(file, "created=%ld\n", session->created);
    fprintf(file, "last_attached=%ld\n", session->last_attached);
    fprintf(file, "window_count=%u\n", session->window_count);
    fprintf(file, "\n");
    
    window_t *window = session->windows;
    int window_idx = 0;
    
    while (window) {
        fprintf(file, "[window_%d]\n", window_idx);
        fprintf(file, "id=%u\n", window->id);
        fprintf(file, "name=%s\n", window->name);
        fprintf(file, "width=%u\n", window->width);
        fprintf(file, "height=%u\n", window->height);
        fprintf(file, "pane_count=%u\n", window->pane_count);
        fprintf(file, "active=%s\n", (window == session->active_window) ? "true" : "false");
        fprintf(file, "\n");
        
        pane_t *pane = window->panes;
        int pane_idx = 0;
        
        while (pane) {
            fprintf(file, "[window_%d_pane_%d]\n", window_idx, pane_idx);
            fprintf(file, "id=%u\n", pane->id);
            fprintf(file, "pid=%d\n", pane->pid);
            fprintf(file, "width=%u\n", pane->width);
            fprintf(file, "height=%u\n", pane->height);
            fprintf(file, "cursor_x=%u\n", pane->cursor_x);
            fprintf(file, "cursor_y=%u\n", pane->cursor_y);
            fprintf(file, "state=%d\n", pane->state);
            fprintf(file, "active=%s\n", (pane == window->active_pane) ? "true" : "false");
            fprintf(file, "\n");
            
            pane = pane->next;
            pane_idx++;
        }
        
        window = window->next;
        window_idx++;
    }
    
    fclose(file);
    
    log_info("Saved session state for %s to %s", session->name, file_path);
    return 0;
}

session_t* load_session_state(const char *session_name) {
    if (!session_name) return NULL;
    
    char *file_path = get_session_file_path(session_name);
    FILE *file = fopen(file_path, "r");
    if (!file) {
        log_info("No saved state found for session %s", session_name);
        return NULL;
    }
    
    session_t *session = NULL;
    window_t *current_window = NULL;
    pane_t *current_pane = NULL;
    char line[1024];
    
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char key[256], value[768];
        if (sscanf(line, "%255[^=]=%767s", key, value) != 2) continue;
        
        if (strcmp(key, "session_name") == 0) {
            session = session_create(value);
            if (!session) {
                fclose(file);
                return NULL;
            }
        } else if (session && strcmp(key, "created") == 0) {
            session->created = atol(value);
        } else if (session && strcmp(key, "last_attached") == 0) {
            session->last_attached = atol(value);
        }
    }
    
    fclose(file);
    
    if (session) {
        log_info("Loaded session state for %s from %s", session_name, file_path);
    }
    
    return session;
}

int delete_session_state(const char *session_name) {
    if (!session_name) return -1;
    
    char *file_path = get_session_file_path(session_name);
    if (unlink(file_path) == -1) {
        if (errno != ENOENT) {
            log_error("Failed to delete session file %s: %s", file_path, strerror(errno));
            return -1;
        }
    }
    
    log_info("Deleted session state file for %s", session_name);
    return 0;
}

int list_saved_sessions(char *output, int max_len) {
    if (!output) return -1;
    
    if (ensure_persist_dir() != 0) {
        return -1;
    }
    
    DIR *dir = opendir(PERSIST_DIR);
    if (!dir) {
        log_error("Failed to open persist directory: %s", strerror(errno));
        return -1;
    }
    
    int pos = 0;
    struct dirent *entry;
    
    pos += snprintf(output + pos, max_len - pos, "Saved sessions:\n");
    
    while ((entry = readdir(dir)) != NULL && pos < max_len - 1) {
        if (strstr(entry->d_name, ".session")) {
            char session_name[256];
            strncpy(session_name, entry->d_name, sizeof(session_name));
            
            char *dot = strrchr(session_name, '.');
            if (dot) *dot = '\0';
            
            pos += snprintf(output + pos, max_len - pos, "  %s\n", session_name);
        }
    }
    
    closedir(dir);
    output[pos] = '\0';
    
    return 0;
}

void cleanup_session_persistence(void) {
    session_t *session = server->sessions;
    while (session) {
        save_session_state(session);
        session = session->next;
    }
}