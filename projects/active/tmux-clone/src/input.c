#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/select.h>
#include "../include/tmux.h"

#define CTRL(c) ((c) & 037)

typedef struct key_binding {
    int key;
    char *command;
    struct key_binding *next;
} key_binding_t;

static key_binding_t *key_bindings = NULL;
static int prefix_mode = 0;
static int prefix_key = CTRL('b');

static void add_key_binding(int key, const char *command) {
    key_binding_t *binding = malloc(sizeof(key_binding_t));
    if (!binding) return;
    
    binding->key = key;
    binding->command = strdup(command);
    binding->next = key_bindings;
    key_bindings = binding;
}

static void init_default_bindings(void) {
    if (key_bindings) return;
    
    add_key_binding('c', "new-window");
    add_key_binding('n', "next-window");
    add_key_binding('p', "previous-window");
    add_key_binding('d', "detach-client");
    add_key_binding('&', "kill-window");
    add_key_binding('x', "kill-pane");
    add_key_binding('%', "split-window -h");
    add_key_binding('"', "split-window -v");
    add_key_binding(':', "command-prompt");
    add_key_binding('?', "list-keys");
}

static key_binding_t* find_key_binding(int key) {
    key_binding_t *binding = key_bindings;
    while (binding) {
        if (binding->key == key) {
            return binding;
        }
        binding = binding->next;
    }
    return NULL;
}

int process_key_input(client_t *client, int key) {
    if (!client) return 0;
    
    init_default_bindings();
    
    if (prefix_mode) {
        prefix_mode = 0;
        
        key_binding_t *binding = find_key_binding(key);
        if (binding) {
            message_t msg;
            msg.type = MSG_COMMAND;
            strcpy(msg.data, binding->command);
            msg.length = strlen(msg.data);
            
            server_handle_client(client, &msg);
            return 1;
        } else {
            log_info("Unknown key binding: %c (%d)", key, key);
            return 0;
        }
    }
    
    if (key == prefix_key) {
        prefix_mode = 1;
        return 1;
    }
    
    if (client->session && client->session->active_window && 
        client->session->active_window->active_pane) {
        pane_t *pane = client->session->active_window->active_pane;
        
        if (pane->master_fd >= 0) {
            char c = key;
            write(pane->master_fd, &c, 1);
            return 1;
        }
    }
    
    return 0;
}

int setup_terminal_raw_mode(int fd) {
    struct termios term;
    
    if (tcgetattr(fd, &term) != 0) {
        return -1;
    }
    
    term.c_lflag &= ~(ICANON | ECHO | ISIG);
    term.c_iflag &= ~(IXON | ICRNL);
    term.c_oflag &= ~OPOST;
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    
    if (tcsetattr(fd, TCSAFLUSH, &term) != 0) {
        return -1;
    }
    
    return 0;
}

int restore_terminal_mode(int fd) {
    struct termios term;
    
    if (tcgetattr(fd, &term) != 0) {
        return -1;
    }
    
    term.c_lflag |= (ICANON | ECHO | ISIG);
    term.c_iflag |= (IXON | ICRNL);
    term.c_oflag |= OPOST;
    
    if (tcsetattr(fd, TCSAFLUSH, &term) != 0) {
        return -1;
    }
    
    return 0;
}

void cleanup_key_bindings(void) {
    while (key_bindings) {
        key_binding_t *next = key_bindings->next;
        free(key_bindings->command);
        free(key_bindings);
        key_bindings = next;
    }
}