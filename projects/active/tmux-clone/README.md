# TMUX Clone

A lightweight terminal multiplexer implementation inspired by tmux, written in C.

## Features

- **Session Management**: Create, attach, detach, and manage multiple terminal sessions
- **Window and Pane Support**: Split windows into multiple panes for better productivity
- **Client-Server Architecture**: Detach and reattach to sessions without losing work
- **Terminal Emulation**: Basic terminal emulation with screen rendering
- **Key Bindings**: Configurable key bindings with default tmux-like shortcuts
- **Session Persistence**: Save and restore session state across restarts
- **Process Management**: Proper handling of shell processes and cleanup

## Architecture

The system follows a client-server model similar to tmux:

- **Server**: Manages sessions, windows, panes, and handles client connections
- **Client**: Connects to server to send commands and receive output
- **Sessions**: Contain one or more windows
- **Windows**: Contain one or more panes
- **Panes**: Individual terminal instances running shell processes

## Building

### Prerequisites

- GCC compiler
- GNU Make
- libutil development headers (for pty support)

### Compile

```bash
make
```

For debug build:
```bash
make debug
```

### Install

```bash
make install
```

## Usage

### Start a new session
```bash
./bin/tmux-clone new-session [session-name]
```

### Attach to existing session
```bash
./bin/tmux-clone attach [session-name]
```

### List sessions
```bash
./bin/tmux-clone list-sessions
```

### Start server manually
```bash
./bin/tmux-clone -s
```

### Start server as daemon
```bash
./bin/tmux-clone -s -d
```

## Key Bindings

Default prefix key is `Ctrl-b`, followed by:

- `c` - Create new window
- `n` - Next window  
- `p` - Previous window
- `d` - Detach from session
- `&` - Kill current window
- `x` - Kill current pane
- `%` - Split window horizontally
- `"` - Split window vertically
- `:` - Command prompt
- `?` - List key bindings

## File Structure

```
tmux-clone/
├── include/
│   └── tmux.h          # Main header with data structures
├── src/
│   ├── main.c          # Entry point and command parsing
│   ├── server.c        # Server implementation
│   ├── client.c        # Client communication
│   ├── session.c       # Session management
│   ├── window.c        # Window management
│   ├── pane.c          # Pane management and pty handling
│   ├── screen.c        # Terminal emulation and rendering
│   ├── input.c         # Key bindings and input handling
│   ├── persist.c       # Session persistence
│   └── utils.c         # Logging utilities
├── Makefile            # Build system
└── README.md          # This file
```

## Technical Details

### Communication Protocol

The client-server communication uses Unix domain sockets with a simple message protocol:

```c
typedef struct {
    message_type_t type;
    uint32_t length;
    char data[BUFFER_SIZE];
} message_t;
```

### Terminal Emulation

Basic terminal emulation supports:
- Character output and cursor positioning
- Basic escape sequences (clear screen, cursor movement)
- Line scrolling and buffer management
- Raw terminal mode for proper key handling

### Process Management

Each pane runs in its own pseudo-terminal (pty) with:
- Proper signal handling for child processes
- Non-blocking I/O for responsive interaction
- Process cleanup on pane destruction

## Limitations

This is a simplified implementation compared to full tmux:

- Basic terminal emulation (no advanced features like mouse support)
- Limited escape sequence support
- No configuration file support
- No copy/paste mode
- No status bar
- Basic session persistence (metadata only)

## Development

### Debugging

Enable debug mode:
```bash
make debug
```

Check logs:
```bash
tail -f /tmp/tmux-clone.log
```

### Testing

The system creates socket files in `/tmp/` and session files in `/tmp/tmux-clone-sessions/`.

Clean up test files:
```bash
rm /tmp/tmux-clone-*
rm -rf /tmp/tmux-clone-sessions/
```

## License

This project is for educational purposes demonstrating terminal multiplexer implementation concepts.