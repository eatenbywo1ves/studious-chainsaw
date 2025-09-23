#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pty.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <termios.h>
#include "../include/tmux.h"

pane_t* pane_create(window_t *window) {
    if (!window) return NULL;

    pane_t *pane = calloc(1, sizeof(pane_t));
    if (!pane) {
        log_error("Failed to allocate pane");
        return NULL;
    }

    pane->id = server->next_pane_id++;
    pane->window = window;
    pane->width = window->width;
    pane->height = window->height;
    pane->cursor_x = 0;
    pane->cursor_y = 0;
    pane->state = PANE_STATE_RUNNING;
    pane->master_fd = -1;
    pane->slave_fd = -1;
    
    pane->buffer_size = pane->width * pane->height;
    pane->buffer = calloc(pane->buffer_size, sizeof(char));
    if (!pane->buffer) {
        log_error("Failed to allocate pane buffer");
        free(pane);
        return NULL;
    }

    pane->next = window->panes;
    window->panes = pane;
    window->pane_count++;

    if (!window->active_pane) {
        window->active_pane = pane;
    }

    log_info("Created pane %d in window %s", pane->id, window->name);
    return pane;
}

void pane_destroy(pane_t *pane) {
    if (!pane) return;

    log_info("Destroying pane %d", pane->id);

    if (pane->pid > 0) {
        kill(pane->pid, SIGTERM);
        waitpid(pane->pid, NULL, WNOHANG);
    }

    if (pane->master_fd >= 0) {
        close(pane->master_fd);
    }
    
    if (pane->slave_fd >= 0) {
        close(pane->slave_fd);
    }

    window_t *window = pane->window;
    if (window) {
        pane_t *current = window->panes;
        pane_t *prev = NULL;

        while (current) {
            if (current == pane) {
                if (prev) {
                    prev->next = current->next;
                } else {
                    window->panes = current->next;
                }
                window->pane_count--;

                if (window->active_pane == pane) {
                    window->active_pane = window->panes;
                }
                break;
            }
            prev = current;
            current = current->next;
        }
    }

    if (pane->buffer) {
        free(pane->buffer);
    }

    free(pane);
}

int pane_spawn_shell(pane_t *pane) {
    if (!pane) return -1;

    struct winsize ws;
    ws.ws_row = pane->height;
    ws.ws_col = pane->width;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    if (openpty(&pane->master_fd, &pane->slave_fd, NULL, NULL, &ws) == -1) {
        log_error("Failed to create pty for pane %d", pane->id);
        return -1;
    }

    fcntl(pane->master_fd, F_SETFL, O_NONBLOCK);

    pane->pid = fork();
    if (pane->pid == -1) {
        log_error("Failed to fork for pane %d", pane->id);
        close(pane->master_fd);
        close(pane->slave_fd);
        return -1;
    }

    if (pane->pid == 0) {
        close(pane->master_fd);
        
        setsid();
        
        if (ioctl(pane->slave_fd, TIOCSCTTY, 0) == -1) {
            perror("ioctl TIOCSCTTY");
            exit(1);
        }

        dup2(pane->slave_fd, STDIN_FILENO);
        dup2(pane->slave_fd, STDOUT_FILENO);
        dup2(pane->slave_fd, STDERR_FILENO);

        if (pane->slave_fd > STDERR_FILENO) {
            close(pane->slave_fd);
        }

        char *shell = getenv("SHELL");
        if (!shell) {
            shell = "/bin/sh";
        }

        execlp(shell, shell, NULL);
        perror("execlp");
        exit(1);
    }

    close(pane->slave_fd);
    pane->slave_fd = -1;

    log_info("Spawned shell (pid: %d) for pane %d", pane->pid, pane->id);
    return 0;
}