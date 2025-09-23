#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/tmux.h"

session_t* session_create(const char *name) {
    session_t *session = calloc(1, sizeof(session_t));
    if (!session) {
        log_error("Failed to allocate session");
        return NULL;
    }

    session->id = server->next_session_id++;
    session->name = strdup(name ? name : "default");
    session->created = time(NULL);
    session->last_attached = 0;
    session->window_count = 0;

    session->next = server->sessions;
    server->sessions = session;

    log_info("Created session %s (id: %d)", session->name, session->id);
    return session;
}

void session_destroy(session_t *session) {
    if (!session) return;

    log_info("Destroying session %s", session->name);

    while (session->windows) {
        window_t *next = session->windows->next;
        window_destroy(session->windows);
        session->windows = next;
    }

    if (session->name) {
        free(session->name);
    }

    session_t *current = server->sessions;
    session_t *prev = NULL;

    while (current) {
        if (current == session) {
            if (prev) {
                prev->next = current->next;
            } else {
                server->sessions = current->next;
            }
            break;
        }
        prev = current;
        current = current->next;
    }

    free(session);
}

session_t* session_find(const char *name) {
    if (!name) return NULL;

    session_t *session = server->sessions;
    while (session) {
        if (strcmp(session->name, name) == 0) {
            return session;
        }
        session = session->next;
    }

    return NULL;
}

session_t* session_find_by_id(uint32_t id) {
    session_t *session = server->sessions;
    while (session) {
        if (session->id == id) {
            return session;
        }
        session = session->next;
    }

    return NULL;
}