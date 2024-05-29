#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>

#define BUFFER_SIZE 1024

/**
 * Creates and binds a server socket to the specified port.
 * 
 * @param port The port number to bind the server socket to.
 * @return The file descriptor of the server socket on success, -1 on failure.
 */
int create_and_bind_server_socket(int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "Binding to port %d failed\n", port);
        close(server_fd);
        return -1;
    }

    return server_fd;
}

/**
 * Accepts a new connection on the given server socket.
 * 
 * @param server_fd The file descriptor of the server socket.
 * @return The file descriptor of the accepted connection, or -1 on failure.
 */
int accept_connection(int server_fd) {
    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);

    int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
    if (new_socket < 0) {
        perror("Accept failed");
    }

    return new_socket;
}

/**
 * Echos received data back to the sender.
 * 
 * @param client_socket The file descriptor of the client socket.
 * @return Returns the bytes read, or 0 for graceful shutdown, or -1 for error.
 */
int echo_client(int client_socket) {
    char buffer[BUFFER_SIZE + 1];
    int bytes_read;

    while ((bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("Received message: %s\n", buffer);

        if (write(client_socket, buffer, bytes_read) < 0) {
            perror("Failed writing message to client");
            return -1;
        }
    }

    if (bytes_read < 0) {
        perror("Failed reading bytes");
        return -1;
    }

    shutdown(client_socket, SHUT_RDWR);
    close(client_socket);
    return bytes_read;
}

/**
 * Validates the port number argument.
 * 
 * @param port The port number as a string.
 * @return The port number as an integer on success, -1 on failure.
 */
int validate_port_argument(char *port) {
    char *endptr;
    long port_long = strtol(port, &endptr, 10);

    if (endptr == port || *endptr != '\0') {
        fprintf(stderr, "Invalid port number: %s\n", port);
        return -1;
    }

    if (port_long <= 0 || port_long > 65535) {
        fprintf(stderr, "Port number must be between 1 and 65535\n");
        return -1;
    }

    return (int)port_long;
}

void handle_sigint(int sig) {
    printf("Caught signal %d, shutting down server...\n", sig);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_sigint);
    if (argc < 2 || argv[1] == NULL) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int port = validate_port_argument(argv[1]);
    if (port == -1) {
        return EXIT_FAILURE;
    }

    int server_fd = create_and_bind_server_socket(port);
    if (server_fd == -1) {
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 1) < 0) {
        perror("Listening failed");
        close(server_fd);
        return EXIT_FAILURE;
    }

    printf("Server listening on port %d...\n", port);

    int new_socket = accept_connection(server_fd);
    if (new_socket < 0) {
        close(server_fd);
        return EXIT_FAILURE;
    }

    printf("New connection accepted\n");
    int res = echo_client(new_socket);
    if (res < 0) {
        perror("Echoing client failed");
        close(server_fd);
        return EXIT_FAILURE;
    }

    printf("Client connection closed. Exiting server...\n");
    close(new_socket);
    close(server_fd);

    return EXIT_SUCCESS;
}
