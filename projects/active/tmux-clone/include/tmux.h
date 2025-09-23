#ifndef TMUX_H
#define TMUX_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define TMUX_VERSION "tmux-clone 1.0"
#define TMUX_SOCKET_NAME "tmux-clone"
#define MAX_SESSIONS 256
#define MAX_WINDOWS 1024
#define MAX_PANES 2048
#define MAX_CLIENTS 64
#define BUFFER_SIZE 4096

typedef enum {
    MSG_HANDSHAKE,
    MSG_COMMAND,
    MSG_READY,
    MSG_EXIT,
    MSG_RESIZE,
    MSG_OUTPUT,
    MSG_INPUT,
    MSG_ATTACH,
    MSG_DETACH
} message_type_t;

typedef struct {
    message_type_t type;
    uint32_t length;
    char data[BUFFER_SIZE];
} message_t;

typedef enum {
    PANE_STATE_RUNNING,
    PANE_STATE_DEAD,
    PANE_STATE_SUSPENDED
} pane_state_t;

typedef struct pane {
    uint32_t id;
    pid_t pid;
    int master_fd;
    int slave_fd;
    uint16_t width;
    uint16_t height;
    uint16_t cursor_x;
    uint16_t cursor_y;
    pane_state_t state;
    char *buffer;
    size_t buffer_size;
    struct pane *next;
    struct window *window;
} pane_t;

typedef struct window {
    uint32_t id;
    char *name;
    uint16_t width;
    uint16_t height;
    pane_t *panes;
    pane_t *active_pane;
    uint32_t pane_count;
    struct window *next;
    struct session *session;
} window_t;

typedef struct session {
    uint32_t id;
    char *name;
    window_t *windows;
    window_t *active_window;
    uint32_t window_count;
    time_t created;
    time_t last_attached;
    struct session *next;
} session_t;

typedef struct client {
    int fd;
    uint32_t id;
    char *terminal;
    uint16_t width;
    uint16_t height;
    session_t *session;
    struct client *next;
} client_t;

typedef struct server_state {
    int socket_fd;
    session_t *sessions;
    client_t *clients;
    uint32_t next_session_id;
    uint32_t next_window_id;
    uint32_t next_pane_id;
    uint32_t next_client_id;
    int running;
} server_state_t;

extern server_state_t *server;

session_t* session_create(const char *name);
void session_destroy(session_t *session);
session_t* session_find(const char *name);
session_t* session_find_by_id(uint32_t id);

window_t* window_create(session_t *session, const char *name);
void window_destroy(window_t *window);
window_t* window_find(session_t *session, const char *name);

pane_t* pane_create(window_t *window);
void pane_destroy(pane_t *pane);
int pane_spawn_shell(pane_t *pane);

client_t* client_create(int fd);
void client_destroy(client_t *client);
void client_attach(client_t *client, session_t *session);
void client_detach(client_t *client);

int server_init(void);
int server_start(void);
void server_cleanup(void);
int server_accept_client(void);
void server_handle_client(client_t *client, message_t *msg);

int client_connect(void);
int client_send_message(int fd, message_type_t type, const char *data);
int client_receive_message(int fd, message_t *msg);

void log_info(const char *format, ...);
void log_error(const char *format, ...);

void screen_process_output(pane_t *pane, const char *data, int len);
void screen_render_pane(pane_t *pane, char *output, int max_len);

#endif