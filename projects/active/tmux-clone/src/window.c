#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pty.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "../include/tmux.h"

window_t* window_create(session_t *session, const char *name) {
    if (!session) return NULL;

    window_t *window = calloc(1, sizeof(window_t));
    if (!window) {
        log_error("Failed to allocate window");
        return NULL;
    }

    window->id = server->next_window_id++;
    window->name = strdup(name ? name : "unnamed");
    window->width = 80;
    window->height = 24;
    window->session = session;
    window->pane_count = 0;

    window->next = session->windows;
    session->windows = window;
    session->window_count++;

    if (!session->active_window) {
        session->active_window = window;
    }

    log_info("Created window %s (id: %d) in session %s", window->name, window->id, session->name);
    return window;
}

void window_destroy(window_t *window) {
    if (!window) return;

    log_info("Destroying window %s", window->name);

    while (window->panes) {
        pane_t *next = window->panes->next;
        pane_destroy(window->panes);
        window->panes = next;
    }

    session_t *session = window->session;
    if (session) {
        window_t *current = session->windows;
        window_t *prev = NULL;

        while (current) {
            if (current == window) {
                if (prev) {
                    prev->next = current->next;
                } else {
                    session->windows = current->next;
                }
                session->window_count--;

                if (session->active_window == window) {
                    session->active_window = session->windows;
                }
                break;
            }
            prev = current;
            current = current->next;
        }
    }

    if (window->name) {
        free(window->name);
    }

    free(window);
}

window_t* window_find(session_t *session, const char *name) {
    if (!session || !name) return NULL;

    window_t *window = session->windows;
    while (window) {
        if (strcmp(window->name, name) == 0) {
            return window;
        }
        window = window->next;
    }

    return NULL;
}