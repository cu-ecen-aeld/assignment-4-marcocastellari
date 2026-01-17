#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>

 // CONFIGURATION
#define SERVER_PORT      "9000"
#define BACKLOG          10
#define CHUNK_SIZE       4096
#define DATA_FILE        "/var/tmp/aesdsocketdata"
#define PIDFILE          "/tmp/aesdsocket.pid"

static volatile sig_atomic_t g_exit_requested = 0;

// SIGNAL HANDLERS
void reap_zombie_children(int sig)
{
    (void)sig;
    int saved_errno = errno;
    pid_t pid;
    
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        syslog(LOG_DEBUG, "Child process %d reaped", pid);
    }
    
    if (pid == -1 && errno != ECHILD) {
        syslog(LOG_ERR, "waitpid error: %s", strerror(errno));
    }
    
    errno = saved_errno;
}

void request_graceful_shutdown(int sig)
{
    (void)sig;
    g_exit_requested = 1;
}

// DAEMON PROCESS MANAGEMENT
static int create_daemon_pidfile(void)
{
    int fd = open(PIDFILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open pidfile: %s", strerror(errno));
        return -1;
    }

    char buf[32];
    int len = snprintf(buf, sizeof(buf), "%d\n", getpid());
    
    if (write(fd, buf, len) == -1) {
        syslog(LOG_ERR, "Failed to write pidfile: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

static int become_daemon_process(void)
{
    // First fork - parent exits, child continues
    pid_t pid = fork();
    if (pid < 0) {
        perror("first fork");
        return -1;
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS); 
    }

    // Create new session - detach from controlling terminal
    if (setsid() < 0) {
        perror("setsid");
        return -1;
    }

    // Second fork - prevent reacquiring controlling terminal
    pid = fork();
    if (pid < 0) {
        perror("second fork");
        return -1;
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change to root directory to avoid blocking unmounts
    if (chdir("/") != 0) {
        perror("chdir");
        return -1;
    }

    // Redirect standard I/O to /dev/null
    if (freopen("/dev/null", "r", stdin) == NULL ||
        freopen("/dev/null", "w", stdout) == NULL ||
        freopen("/dev/null", "w", stderr) == NULL) {
        perror("freopen");
        return -1;
    }

    // Write PID file for daemon control scripts
    if (create_daemon_pidfile() != 0) {
        syslog(LOG_ERR, "Failed to write pidfile");
        return -1;
    }

    syslog(LOG_INFO, "Daemon started, PID written to %s", PIDFILE);
    return 0;
}

// TCP NETWORK SETUP
static int setup_tcp_server_socket(const char *port)
{
    struct addrinfo hints, *servinfo, *p;
    int sockfd;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE;     // Listen on all interfaces

    int status = getaddrinfo(NULL, port, &hints, &servinfo);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return -1;
    }

    // Try each address until successful bind
    for (p = servinfo; p != NULL; p = p->ai_next) {
        // Create socket endpoint
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            fprintf(stderr, "socket error: %s\n", strerror(errno));
            continue;
        }

        // Allow immediate reuse of address (avoid "Address already in use")
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
            close(sockfd);
            freeaddrinfo(servinfo);
            return -1;
        }

        // Bind socket to address and port
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            fprintf(stderr, "bind error: %s\n", strerror(errno));
            continue;
        }

        // Log successful binding
        struct sockaddr_storage sa;
        socklen_t sa_len = sizeof(sa);
        if (getsockname(sockfd, (struct sockaddr *)&sa, &sa_len) == 0) {
            char host[NI_MAXHOST], service[NI_MAXSERV];
            if (getnameinfo((struct sockaddr *)&sa, sa_len, host, sizeof(host),
                           service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                printf("Server bound to %s:%s\n", host, service);
            }
        }
        
        break; 
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "Failed to bind socket\n");
        return -1;
    }

    // Start listening for connections
    if (listen(sockfd, BACKLOG) == -1) {
        fprintf(stderr, "listen error: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

// FILE OPERATIONS
static int append_packet_to_datafile(const char *filename, const char *data, size_t len)
{
    int fd = open(filename, O_CREAT | O_RDWR | O_APPEND, 0644);
    if (fd == -1) {
        perror("open for append");
        return -1;
    }

    flock(fd, LOCK_EX);  // Exclusive lock for writing

    ssize_t total_written = 0;
    while (total_written < (ssize_t)len) {
        ssize_t n = write(fd, data + total_written, len - total_written);
        if (n == -1) {
            if (errno == EINTR) continue;
            perror("write");
            flock(fd, LOCK_UN);
            close(fd);
            return -1;
        }
        total_written += n;
    }

    flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

static int transmit_file_to_client(int sockfd, const char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open for read");
        return -1;
    }

    flock(fd, LOCK_SH);  // Shared lock for reading

    char buf[CHUNK_SIZE];
    ssize_t bytes_read;
    
    while ((bytes_read = read(fd, buf, CHUNK_SIZE)) > 0) {
        ssize_t total_sent = 0;
        
        while (total_sent < bytes_read) {
            ssize_t n = send(sockfd, buf + total_sent, bytes_read - total_sent, 0);
            if (n == -1) {
                if (errno == EINTR) continue;
                perror("send");
                flock(fd, LOCK_UN);
                close(fd);
                return -1;
            }
            total_sent += n;
        }
    }

    if (bytes_read == -1) {
        perror("read");
        flock(fd, LOCK_UN);
        close(fd);
        return -1;
    }

    flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

// DYNAMIC BUFFER MANAGEMENT
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} packet_buffer_t;

static void initialize_packet_buffer(packet_buffer_t *buf)
{
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

static int append_data_to_buffer(packet_buffer_t *buf, const char *data, size_t len)
{
    if (buf->size + len > buf->capacity) {
        size_t new_capacity = buf->capacity + len + CHUNK_SIZE;
        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) {
            perror("realloc");
            return -1;
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    return 0;
}

static void remove_processed_bytes(packet_buffer_t *buf, size_t len)
{
    if (len >= buf->size) {
        buf->size = 0;
    } else {
        memmove(buf->data, buf->data + len, buf->size - len);
        buf->size -= len;
    }
}

static void cleanup_packet_buffer(packet_buffer_t *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

// CLIENT CONNECTION HANDLER
static void serve_client_connection(int client_sockfd, const char *client_host)
{
    packet_buffer_t buffer;
    initialize_packet_buffer(&buffer);
    
    char temp[CHUNK_SIZE];
    ssize_t bytes_read;

    // Receive data from client in chunks
    while ((bytes_read = recv(client_sockfd, temp, CHUNK_SIZE, 0)) > 0) {
        // Append received data to buffer
        if (append_data_to_buffer(&buffer, temp, bytes_read) != 0) {
            cleanup_packet_buffer(&buffer);
            close(client_sockfd);
            syslog(LOG_INFO, "Closed connection from %s", client_host);
            _exit(EXIT_FAILURE);
        }

        // Scan buffer for complete packets (newline-delimited)
        size_t i = 0;
        while (i < buffer.size) {
            if (buffer.data[i] == '\n') {
                size_t packet_len = i + 1;

                // Write packet to persistent file
                if (append_packet_to_datafile(DATA_FILE, buffer.data, packet_len) != 0) {
                    cleanup_packet_buffer(&buffer);
                    close(client_sockfd);
                    syslog(LOG_INFO, "Closed connection from %s", client_host);
                    _exit(EXIT_FAILURE);
                }

                // Send entire file contents back to client
                if (transmit_file_to_client(client_sockfd, DATA_FILE) != 0) {
                    cleanup_packet_buffer(&buffer);
                    close(client_sockfd);
                    syslog(LOG_INFO, "Closed connection from %s", client_host);
                    _exit(EXIT_FAILURE);
                }

                // Remove processed packet from buffer
                remove_processed_bytes(&buffer, packet_len);
                i = 0;  // Restart scan from beginning
            } else {
                i++;
            }
        }
    }

    if (bytes_read == -1) {
        perror("recv");
    }

    cleanup_packet_buffer(&buffer);
    close(client_sockfd);
    syslog(LOG_INFO, "Closed connection from %s", client_host);
    _exit(EXIT_SUCCESS);
}

// SIGNAL CONFIGURATION
static int install_signal_handlers(void)
{
    struct sigaction sa;

    // SIGCHLD handler - reap zombie children automatically
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = reap_zombie_children;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;  // Restart interrupted syscalls
    
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        fprintf(stderr, "sigaction(SIGCHLD) failed: %s\n", strerror(errno));
        return -1;
    }

    // SIGINT and SIGTERM handlers - initiate graceful shutdown
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = request_graceful_shutdown;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // Don't restart - allow clean exit
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "sigaction(SIGINT) failed: %s\n", strerror(errno));
        return -1;
    }
    
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        fprintf(stderr, "sigaction(SIGTERM) failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// MAIN
static void accept_and_dispatch_connections(int listen_sockfd)
{
    struct sockaddr_storage client_addr;
    socklen_t addr_len;
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];

    printf("Waiting for connections...\n");

    while (!g_exit_requested) {
        addr_len = sizeof(client_addr);
        int client_sockfd = accept(listen_sockfd, (struct sockaddr *)&client_addr, &addr_len);

        // Check for accept errors
        if (client_sockfd == -1) {
            if (errno == EINTR && g_exit_requested) {
                break;  // Interrupted by shutdown signal
            }
            syslog(LOG_ERR, "accept error: %s", strerror(errno));
            continue;
        }

        // Extract client address information for logging
        int rc = getnameinfo((struct sockaddr *)&client_addr, addr_len,
                            host, sizeof(host), service, sizeof(service),
                            NI_NUMERICHOST | NI_NUMERICSERV);
        
        if (rc != 0) {
            syslog(LOG_WARNING, "getnameinfo error: %s", gai_strerror(rc));
            snprintf(host, sizeof(host), "unknown");
        }

        syslog(LOG_INFO, "Accepted connection from %s", host);

        // Fork child process to handle client
        pid_t pid = fork();
        
        if (pid == 0) {
            // Child process
            close(listen_sockfd);  // Child doesn't need listening socket
            serve_client_connection(client_sockfd, host);
            // serve_client_connection() never returns
        } else if (pid > 0) {
            // Parent process
            close(client_sockfd);  // Parent doesn't need client socket
        } else {
            // Fork failed
            syslog(LOG_ERR, "fork error: %s", strerror(errno));
            close(client_sockfd);
        }
    }

    syslog(LOG_INFO, "Caught signal, exiting");
}

int main(int argc, char *argv[])
{
    int daemon_mode = 0;
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "d")) != -1) {
        switch (opt) {
            case 'd':
                daemon_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-d]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    printf("Starting server (daemon_mode = %d)...\n", daemon_mode);

    // Initialize system logging
    openlog("aesdsocket", LOG_PID | LOG_NDELAY, LOG_USER);

    // Create and configure server socket
    int listen_sockfd = setup_tcp_server_socket(SERVER_PORT);
    if (listen_sockfd == -1) {
        closelog();
        return -1;
    }

    // Configure signal handling
    if (install_signal_handlers() != 0) {
        close(listen_sockfd);
        closelog();
        return -1;
    }

    // Transform into daemon if requested
    if (daemon_mode) {
        if (become_daemon_process() != 0) {
            close(listen_sockfd);
            closelog();
            return -1;
        }
    }

    // Run main server accept loop
    accept_and_dispatch_connections(listen_sockfd);

    // Cleanup on shutdown
    close(listen_sockfd);
    unlink(DATA_FILE);
    closelog();

    return 0;
}