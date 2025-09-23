#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/wait.h>
#include "../include/tmux.h"

static int server_mode = 0;
static int daemon_mode = 0;

void print_usage(const char *program_name) {
    printf("Usage: %s [options] [command]\n", program_name);
    printf("Options:\n");
    printf("  -s              Start server mode\n");
    printf("  -d              Daemon mode\n");
    printf("  -h              Show this help\n");
    printf("  -v              Show version\n");
    printf("\nCommands:\n");
    printf("  new-session [name]    Create new session\n");
    printf("  attach [session]      Attach to session\n");
    printf("  detach                Detach from session\n");
    printf("  list-sessions         List all sessions\n");
    printf("  kill-session [name]   Kill session\n");
}

void print_version(void) {
    printf("%s\n", TMUX_VERSION);
}

int start_server_daemon(void) {
    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            log_error("Failed to fork daemon process");
            return -1;
        }
        
        if (pid > 0) {
            printf("Server started with PID %d\n", pid);
            exit(0);
        }
        
        setsid();
        
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }
    
    if (server_init() != 0) {
        return -1;
    }
    
    log_info("Starting tmux server");
    return server_start();
}

int execute_client_command(int argc, char *argv[]) {
    int sock_fd = client_connect();
    if (sock_fd < 0) {
        printf("No server running. Starting server...\n");
        
        pid_t pid = fork();
        if (pid < 0) {
            log_error("Failed to fork server process");
            return -1;
        }
        
        if (pid == 0) {
            server_mode = 1;
            daemon_mode = 1;
            return start_server_daemon();
        }
        
        sleep(1);
        
        sock_fd = client_connect();
        if (sock_fd < 0) {
            printf("Failed to connect to server\n");
            return -1;
        }
    }
    
    client_send_message(sock_fd, MSG_HANDSHAKE, "client");
    
    message_t response;
    if (client_receive_message(sock_fd, &response) > 0) {
        if (response.type != MSG_READY) {
            printf("Server not ready\n");
            close(sock_fd);
            return -1;
        }
    }
    
    char command[BUFFER_SIZE];
    if (argc > 1) {
        strncpy(command, argv[1], sizeof(command) - 1);
        command[sizeof(command) - 1] = '\0';
        
        for (int i = 2; i < argc; i++) {
            strncat(command, " ", sizeof(command) - strlen(command) - 1);
            strncat(command, argv[i], sizeof(command) - strlen(command) - 1);
        }
    } else {
        strcpy(command, "new-session");
    }
    
    client_send_message(sock_fd, MSG_COMMAND, command);
    
    if (client_receive_message(sock_fd, &response) > 0) {
        printf("%s\n", response.data);
    }
    
    close(sock_fd);
    return 0;
}

void signal_handler(int sig) {
    if (sig == SIGCHLD) {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0);
    } else if (sig == SIGTERM || sig == SIGINT) {
        if (server && server_mode) {
            server->running = 0;
        }
    }
}

int main(int argc, char *argv[]) {
    int opt;
    
    signal(SIGCHLD, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    while ((opt = getopt(argc, argv, "sdhv")) != -1) {
        switch (opt) {
            case 's':
                server_mode = 1;
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (server_mode) {
        return start_server_daemon();
    } else {
        return execute_client_command(argc - optind, argv + optind);
    }
}