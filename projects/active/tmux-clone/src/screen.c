#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include "../include/tmux.h"

#define ESC_SEQ_MAX 32

typedef struct {
    char *data;
    int width;
    int height;
    int cursor_x;
    int cursor_y;
    int dirty;
} screen_t;

static screen_t *screen_create(int width, int height) {
    screen_t *screen = calloc(1, sizeof(screen_t));
    if (!screen) return NULL;

    screen->width = width;
    screen->height = height;
    screen->cursor_x = 0;
    screen->cursor_y = 0;
    screen->dirty = 1;
    
    screen->data = calloc(width * height, sizeof(char));
    if (!screen->data) {
        free(screen);
        return NULL;
    }

    memset(screen->data, ' ', width * height);
    return screen;
}

static void screen_destroy(screen_t *screen) {
    if (!screen) return;
    if (screen->data) free(screen->data);
    free(screen);
}

static void screen_clear(screen_t *screen) {
    if (!screen) return;
    memset(screen->data, ' ', screen->width * screen->height);
    screen->cursor_x = 0;
    screen->cursor_y = 0;
    screen->dirty = 1;
}

static void screen_put_char(screen_t *screen, char c) {
    if (!screen) return;
    
    if (c == '\n') {
        screen->cursor_y++;
        screen->cursor_x = 0;
        if (screen->cursor_y >= screen->height) {
            memmove(screen->data, screen->data + screen->width, 
                   (screen->height - 1) * screen->width);
            memset(screen->data + (screen->height - 1) * screen->width, ' ', screen->width);
            screen->cursor_y = screen->height - 1;
        }
    } else if (c == '\r') {
        screen->cursor_x = 0;
    } else if (c == '\b') {
        if (screen->cursor_x > 0) {
            screen->cursor_x--;
        }
    } else if (c >= 32 && c < 127) {
        if (screen->cursor_x >= screen->width) {
            screen->cursor_x = 0;
            screen->cursor_y++;
            if (screen->cursor_y >= screen->height) {
                memmove(screen->data, screen->data + screen->width, 
                       (screen->height - 1) * screen->width);
                memset(screen->data + (screen->height - 1) * screen->width, ' ', screen->width);
                screen->cursor_y = screen->height - 1;
            }
        }
        
        screen->data[screen->cursor_y * screen->width + screen->cursor_x] = c;
        screen->cursor_x++;
    }
    
    screen->dirty = 1;
}

static int screen_process_escape(screen_t *screen, const char *seq) {
    if (!screen || !seq) return 0;
    
    if (seq[0] == '[') {
        if (seq[1] == 'H' || (seq[1] == '1' && seq[2] == ';' && seq[3] == '1' && seq[4] == 'H')) {
            screen->cursor_x = 0;
            screen->cursor_y = 0;
            return 1;
        }
        
        if (seq[1] == '2' && seq[2] == 'J') {
            screen_clear(screen);
            return 1;
        }
        
        if (seq[1] == 'K') {
            int start = screen->cursor_y * screen->width + screen->cursor_x;
            int end = (screen->cursor_y + 1) * screen->width;
            memset(screen->data + start, ' ', end - start);
            screen->dirty = 1;
            return 1;
        }
    }
    
    return 0;
}

void screen_process_output(pane_t *pane, const char *data, int len) {
    if (!pane || !data) return;
    
    screen_t *screen = (screen_t*)pane->buffer;
    if (!screen) {
        screen = screen_create(pane->width, pane->height);
        pane->buffer = (char*)screen;
        if (!screen) return;
    }
    
    static char escape_buf[ESC_SEQ_MAX];
    static int escape_len = 0;
    static int in_escape = 0;
    
    for (int i = 0; i < len; i++) {
        char c = data[i];
        
        if (in_escape) {
            escape_buf[escape_len++] = c;
            escape_buf[escape_len] = '\0';
            
            if (escape_len >= ESC_SEQ_MAX - 1 || 
                (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                screen_process_escape(screen, escape_buf);
                escape_len = 0;
                in_escape = 0;
            }
        } else if (c == '\033') {
            in_escape = 1;
            escape_len = 0;
        } else {
            screen_put_char(screen, c);
        }
    }
    
    pane->cursor_x = screen->cursor_x;
    pane->cursor_y = screen->cursor_y;
}

void screen_render_pane(pane_t *pane, char *output, int max_len) {
    if (!pane || !output) return;
    
    screen_t *screen = (screen_t*)pane->buffer;
    if (!screen) return;
    
    int pos = 0;
    
    pos += snprintf(output + pos, max_len - pos, "\033[2J\033[H");
    
    for (int y = 0; y < screen->height && pos < max_len - 1; y++) {
        for (int x = 0; x < screen->width && pos < max_len - 1; x++) {
            output[pos++] = screen->data[y * screen->width + x];
        }
        if (y < screen->height - 1 && pos < max_len - 1) {
            output[pos++] = '\n';
        }
    }
    
    if (pos < max_len - 20) {
        pos += snprintf(output + pos, max_len - pos, "\033[%d;%dH", 
                       screen->cursor_y + 1, screen->cursor_x + 1);
    }
    
    output[pos] = '\0';
}