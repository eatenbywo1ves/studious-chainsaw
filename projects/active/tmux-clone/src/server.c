#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include "../include/tmux.h"

server_state_t *server = NULL;

int server_init(void) {
    server = calloc(1, sizeof(server_state_t));
    if (!server) {
        log_error("Failed to allocate server state");
        return -1;
    }

    server->next_session_id = 1;
    server->next_window_id = 1;
    server->next_pane_id = 1;
    server->next_client_id = 1;
    server->running = 1;

    struct sockaddr_un addr;
    server->socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server->socket_fd == -1) {
        log_error("Failed to create socket: %s", strerror(errno));
        free(server);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/%s-%d", TMUX_SOCKET_NAME, getuid());
    
    unlink(addr.sun_path);

    if (bind(server->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_error("Failed to bind socket: %s", strerror(errno));
        close(server->socket_fd);
        free(server);
        return -1;
    }

    if (listen(server->socket_fd, 5) == -1) {
        log_error("Failed to listen on socket: %s", strerror(errno));
        close(server->socket_fd);
        free(server);
        return -1;
    }

    log_info("Server initialized on socket: %s", addr.sun_path);
    return 0;
}

int server_accept_client(void) {
    int client_fd = accept(server->socket_fd, NULL, NULL);
    if (client_fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_error("Failed to accept client: %s", strerror(errno));
        }
        return -1;
    }

    fcntl(client_fd, F_SETFL, O_NONBLOCK);

    client_t *client = client_create(client_fd);
    if (!client) {
        close(client_fd);
        return -1;
    }

    client->next = server->clients;
    server->clients = client;

    log_info("Client %d connected", client->id);
    return 0;
}

void server_handle_client(client_t *client, message_t *msg) {
    switch (msg->type) {
        case MSG_HANDSHAKE:
            log_info("Handshake from client %d", client->id);
            client_send_message(client->fd, MSG_READY, "");
            break;
        
        case MSG_COMMAND: {
            log_info("Command from client %d: %s", client->id, msg->data);
            
            if (strncmp(msg->data, "new-session", 11) == 0) {
                char session_name[256];
                if (sscanf(msg->data, "new-session %s", session_name) == 1) {
                    session_t *session = session_create(session_name);
                    if (session) {
                        window_t *window = window_create(session, "0");
                        if (window) {
                            pane_t *pane = pane_create(window);
                            if (pane) {
                                pane_spawn_shell(pane);
                                client_attach(client, session);
                                client_send_message(client->fd, MSG_READY, "Session created");
                            }
                        }
                    }
                } else {
                    session_t *session = session_create("default");
                    if (session) {
                        window_t *window = window_create(session, "0");
                        if (window) {
                            pane_t *pane = pane_create(window);
                            if (pane) {
                                pane_spawn_shell(pane);
                                client_attach(client, session);
                                client_send_message(client->fd, MSG_READY, "Session created");
                            }
                        }
                    }
                }
            }
            break;
        }
        
        case MSG_DETACH:
            log_info("Client %d detaching", client->id);
            client_detach(client);
            break;
        
        case MSG_EXIT:
            log_info("Client %d exiting", client->id);
            client_destroy(client);
            break;
        
        default:
            log_error("Unknown message type from client %d", client->id);
            break;
    }
}

int server_start(void) {
    fd_set read_fds;
    int max_fd;
    struct timeval timeout;

    while (server->running) {
        FD_ZERO(&read_fds);
        FD_SET(server->socket_fd, &read_fds);
        max_fd = server->socket_fd;

        client_t *client = server->clients;
        while (client) {
            FD_SET(client->fd, &read_fds);
            if (client->fd > max_fd) {
                max_fd = client->fd;
            }
            client = client->next;
        }

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno != EINTR) {
                log_error("Select failed: %s", strerror(errno));
                break;
            }
            continue;
        }

        if (FD_ISSET(server->socket_fd, &read_fds)) {
            server_accept_client();
        }

        client = server->clients;
        client_t *prev = NULL;
        
        while (client) {
            client_t *next = client->next;
            
            if (FD_ISSET(client->fd, &read_fds)) {
                message_t msg;
                int result = client_receive_message(client->fd, &msg);
                
                if (result <= 0) {
                    log_info("Client %d disconnected", client->id);
                    if (prev) {
                        prev->next = next;
                    } else {
                        server->clients = next;
                    }
                    client_destroy(client);
                    client = next;
                    continue;
                }
                
                server_handle_client(client, &msg);
            }
            
            prev = client;
            client = next;
        }
    }

    return 0;
}

void server_cleanup(void) {
    if (!server) return;

    while (server->clients) {
        client_t *next = server->clients->next;
        client_destroy(server->clients);
        server->clients = next;
    }

    while (server->sessions) {
        session_t *next = server->sessions->next;
        session_destroy(server->sessions);
        server->sessions = next;
    }

    if (server->socket_fd >= 0) {
        close(server->socket_fd);
    }

    free(server);
    server = NULL;
}