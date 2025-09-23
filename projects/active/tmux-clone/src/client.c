#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "../include/tmux.h"

int client_connect(void) {
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        log_error("Failed to create client socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/%s-%d", TMUX_SOCKET_NAME, getuid());

    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        log_error("Failed to connect to server: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

int client_send_message(int fd, message_type_t type, const char *data) {
    message_t msg;
    msg.type = type;
    msg.length = data ? strlen(data) : 0;
    
    if (msg.length >= BUFFER_SIZE) {
        msg.length = BUFFER_SIZE - 1;
    }
    
    if (data && msg.length > 0) {
        memcpy(msg.data, data, msg.length);
    }
    msg.data[msg.length] = '\0';

    ssize_t sent = send(fd, &msg, sizeof(message_t), 0);
    if (sent != sizeof(message_t)) {
        log_error("Failed to send message: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int client_receive_message(int fd, message_t *msg) {
    ssize_t received = recv(fd, msg, sizeof(message_t), 0);
    
    if (received == 0) {
        return 0; 
    }
    
    if (received != sizeof(message_t)) {
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return -1; 
        }
        log_error("Failed to receive message: %s", strerror(errno));
        return -1;
    }

    return received;
}

client_t* client_create(int fd) {
    client_t *client = calloc(1, sizeof(client_t));
    if (!client) {
        log_error("Failed to allocate client");
        return NULL;
    }

    client->fd = fd;
    client->id = server->next_client_id++;
    client->width = 80;
    client->height = 24;
    client->terminal = strdup("xterm-256color");

    return client;
}

void client_destroy(client_t *client) {
    if (!client) return;

    if (client->fd >= 0) {
        close(client->fd);
    }
    
    if (client->terminal) {
        free(client->terminal);
    }
    
    free(client);
}

void client_attach(client_t *client, session_t *session) {
    if (!client || !session) return;
    
    client->session = session;
    session->last_attached = time(NULL);
    
    log_info("Client %d attached to session %s", client->id, session->name);
}

void client_detach(client_t *client) {
    if (!client || !client->session) return;
    
    log_info("Client %d detached from session %s", client->id, client->session->name);
    client->session = NULL;
}