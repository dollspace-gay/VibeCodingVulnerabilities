/*
 * A simple and secure C web server for file uploads.
 *
 * Security Features:
 * - Runs as a non-root user to limit potential damage (Least Privilege).
 * - Sanitizes filenames to prevent directory traversal attacks.
 * - Uses secure temporary files (mkstemp) and atomic rename to prevent race conditions.
 * - Sets restrictive file permissions on uploaded files.
 * - Implements a maximum file size limit to prevent DoS attacks.
 * - Avoids common buffer overflows by using safe string functions and explicit checks.
 * - Handles basic HTTP GET and POST requests.
 *
 * Compilation:
 * gcc -Wall -Wextra -o server server.c
 *
 * Usage (see README.md for detailed setup):
 * sudo ./server <port> <upload_directory> <user>
 */

#define _GNU_SOURCE // For memmem
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

// --- Constants ---
#define BUFFER_SIZE 4096
#define UPLOAD_MAX_FILE_SIZE (10 * 1024 * 1024) // 10 MB
#define MAX_FILENAME_LEN 256
#define MAX_BOUNDARY_LEN 128
#define MAX_FULL_BOUNDARY_LEN (MAX_BOUNDARY_LEN + 4) // Accommodates "--" prefix and null terminator
#define MAX_FILEPATH_LEN 512
#define MAX_HEADER_LEN 512

// --- Enums ---
typedef enum {
    HTTP_STATUS_OK = 200,
    HTTP_STATUS_CREATED = 201,
    HTTP_STATUS_BAD_REQUEST = 400,
    HTTP_STATUS_NOT_FOUND = 404,
    HTTP_STATUS_CONFLICT = 409,
    HTTP_STATUS_PAYLOAD_TOO_LARGE = 413,
    HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
    HTTP_STATUS_NOT_IMPLEMENTED = 501
} HTTPStatus;

// --- Structs ---
// A struct to hold parsed information from a multipart/form-data request
typedef struct {
    char boundary[MAX_FULL_BOUNDARY_LEN];
    char filename[MAX_FILENAME_LEN];
    char *file_data_start;
    ssize_t initial_data_len;
} multipart_data;


// --- Function Prototypes ---
void handle_request(int client_socket, const char *upload_dir);
void handle_get_request(int client_socket, const char *uri);
void handle_post_request(int client_socket, const char *uri, const char *upload_dir, char *request_buffer, ssize_t buffer_len);
void handle_file_upload(int client_socket, const char *upload_dir, char *request_buffer, ssize_t buffer_len);
int parse_multipart_headers(char *request_buffer, ssize_t buffer_len, multipart_data *data, int client_socket);
int stream_file_data(int client_socket, int fd, multipart_data *data);
int create_temp_file(const char *upload_dir, char *temp_filepath_out, size_t temp_filepath_size, int client_socket);
int finalize_upload(const char *upload_dir, const char *temp_filepath, const char *final_filename, int client_socket);
void drop_privileges(const char *username);
void serve_file(int client_socket, const char *filename);
const char* get_content_type(const char* filename);
void send_error_response(int client_socket, HTTPStatus status_code, const char *status_message, const char* body);
void sanitize_filename(char *filename);
int setup_server_socket(int port);

// --- Signal Handler for Graceful Shutdown ---
volatile sig_atomic_t server_running = 1;

void sigint_handler(int signum) {
    (void)signum; // Unused parameter
    server_running = 0;
    printf("\nCaught signal, shutting down gracefully...\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <port> <upload_directory> <user>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    const char *upload_dir = argv[2];
    const char *run_as_user = argv[3];

    // --- Validate User Input ---
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number.\n");
        return 1;
    }
    if (run_as_user == NULL || strlen(run_as_user) == 0) {
        fprintf(stderr, "Error: User argument is missing or empty.\n");
        return 1;
    }

    // --- Environment Setup Check ---
    struct stat st;
    if (stat(upload_dir, &st) == -1 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: Upload directory '%s' does not exist or is not a directory.\n", upload_dir);
        return 1;
    }
    if (getpwnam(run_as_user) == NULL) {
        fprintf(stderr, "Error: User '%s' not found.\n", run_as_user);
        return 1;
    }

    // --- Signal Handling ---
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    // --- Socket Creation and Binding ---
    int server_socket = setup_server_socket(port);
    if (server_socket < 0) {
        fprintf(stderr, "Failed to set up server socket.\n");
        return 1;
    }

    printf("Server starting on port %d, running as root...\n", port);
    drop_privileges(run_as_user);
    printf("Server listening on port %d as user '%s'...\n", port, run_as_user);

    // --- Main Accept Loop ---
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (client_socket < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        printf("Accepted connection from %s\n", inet_ntoa(client_addr.sin_addr));

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_socket);
        } else if (pid == 0) { // Child process
            close(server_socket);
            handle_request(client_socket, upload_dir);
            close(client_socket);
            exit(0);
        } else { // Parent process
            close(client_socket);
        }
    }

    close(server_socket);
    printf("Server shut down.\n");
    return 0;
}

/**
 * @brief Initializes and binds the server socket.
 * @param port The port to listen on.
 * @return The server socket file descriptor, or -1 on failure.
 */
int setup_server_socket(int port) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_socket);
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_socket);
        return -1;
    }

    if (listen(server_socket, 10) < 0) {
        perror("listen");
        close(server_socket);
        return -1;
    }
    return server_socket;
}

/**
 * @brief Main request router. Parses the method and URI and delegates.
 */
void handle_request(int client_socket, const char *upload_dir) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        return; // Client disconnected or error
    }
    buffer[bytes_read] = '\0';

    char method[16], uri[256];
    if (sscanf(buffer, "%15s %255s", method, uri) != 2) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Invalid request line.");
        return;
    }

    if (strcmp(method, "GET") == 0) {
        handle_get_request(client_socket, uri);
    } else if (strcmp(method, "POST") == 0) {
        handle_post_request(client_socket, uri, upload_dir, buffer, bytes_read);
    } else {
        send_error_response(client_socket, HTTP_STATUS_NOT_IMPLEMENTED, "Not Implemented", "Method not implemented.");
    }
}

/**
 * @brief Handles GET requests. Currently only serves index.html.
 */
void handle_get_request(int client_socket, const char *uri) {
    if (strcmp(uri, "/") == 0) {
        serve_file(client_socket, "index.html");
    } else {
        send_error_response(client_socket, HTTP_STATUS_NOT_FOUND, "Not Found", "Resource not found.");
    }
}

/**
 * @brief Handles POST requests. Currently only supports /upload endpoint.
 */
void handle_post_request(int client_socket, const char *uri, const char *upload_dir, char *request_buffer, ssize_t buffer_len) {
    if (strcmp(uri, "/upload") == 0) {
        handle_file_upload(client_socket, upload_dir, request_buffer, buffer_len);
    } else {
        send_error_response(client_socket, HTTP_STATUS_NOT_FOUND, "Not Found", "Endpoint not found.");
    }
}

/**
 * @brief Orchestrates the file upload process.
 */
void handle_file_upload(int client_socket, const char *upload_dir, char *request_buffer, ssize_t buffer_len) {
    multipart_data data = {0};
    if (parse_multipart_headers(request_buffer, buffer_len, &data, client_socket) != 0) {
        return; // Error response already sent
    }

    char temp_filepath[MAX_FILEPATH_LEN];
    int fd = create_temp_file(upload_dir, temp_filepath, sizeof(temp_filepath), client_socket);
    if (fd < 0) {
        return; // Error response sent in helper
    }

    if (stream_file_data(client_socket, fd, &data) != 0) {
        close(fd);
        unlink(temp_filepath); // Clean up on failure
        return; // Error response already sent
    }
    close(fd);

    if (finalize_upload(upload_dir, temp_filepath, data.filename, client_socket) != 0) {
        return; // Error response sent in helper
    }
    
    const char *response = "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\n\r\nFile uploaded successfully.";
    send(client_socket, response, strlen(response), 0);
}

/**
 * @brief Parses multipart/form-data headers to find the boundary and filename.
 * @return 0 on success, -1 on failure. Sends HTTP error on failure.
 */
int parse_multipart_headers(char *request_buffer, ssize_t buffer_len, multipart_data *data, int client_socket) {
    char *content_type_hdr = strstr(request_buffer, "Content-Type: multipart/form-data; boundary=");
    if (!content_type_hdr) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Invalid Content-Type for upload.");
        return -1;
    }
    char boundary_val[MAX_BOUNDARY_LEN];
    if (sscanf(content_type_hdr, "Content-Type: multipart/form-data; boundary=%127s", boundary_val) != 1) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Could not parse boundary.");
        return -1;
    }
    snprintf(data->boundary, sizeof(data->boundary), "--%s", boundary_val);

    char *body_start = strstr(request_buffer, "\r\n\r\n");
    if (!body_start) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Malformed request body.");
        return -1;
    }
    body_start += 4;

    char *filename_ptr = strstr(body_start, "filename=\"");
    if (!filename_ptr) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Filename not found in form data.");
        return -1;
    }
    filename_ptr += 10;
    char *filename_end = strchr(filename_ptr, '"');
    if (!filename_end) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Malformed filename in form data.");
        return -1;
    }

    size_t filename_len = filename_end - filename_ptr;
    if (filename_len >= sizeof(data->filename)) filename_len = sizeof(data->filename) - 1;
    strncpy(data->filename, filename_ptr, filename_len);
    data->filename[filename_len] = '\0';

    if (strlen(data->filename) == 0) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Empty filename provided.");
        return -1;
    }
    sanitize_filename(data->filename);

    data->file_data_start = strstr(filename_end, "\r\n\r\n");
    if (!data->file_data_start) {
        send_error_response(client_socket, HTTP_STATUS_BAD_REQUEST, "Bad Request", "Could not find start of file data.");
        return -1;
    }
    data->file_data_start += 4;
    data->initial_data_len = buffer_len - (data->file_data_start - request_buffer);

    return 0;
}

/**
 * @brief Creates a secure temporary file for the upload.
 * @return File descriptor on success, -1 on failure.
 */
int create_temp_file(const char *upload_dir, char *temp_filepath_out, size_t temp_filepath_size, int client_socket) {
    snprintf(temp_filepath_out, temp_filepath_size, "%s/upload-XXXXXX", upload_dir);
    int fd = mkstemp(temp_filepath_out);
    if (fd < 0) {
        perror("mkstemp");
        send_error_response(client_socket, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error", "Could not create temporary file.");
        return -1;
    }
    return fd;
}

/**
 * @brief Writes the initial data chunk and streams the rest of the file from the socket to the file descriptor.
 * @return 0 on success, -1 on failure. Sends HTTP error on failure.
 */
int stream_file_data(int client_socket, int fd, multipart_data *data) {
    size_t total_written = 0;
    
    // Check for boundary in the initial chunk of data
    char *boundary_in_data = memmem(data->file_data_start, data->initial_data_len, data->boundary, strlen(data->boundary));
    size_t data_to_write = data->initial_data_len;
    if (boundary_in_data) {
        data_to_write = boundary_in_data - data->file_data_start - 2; // -2 for \r\n
    }

    ssize_t written = write(fd, data->file_data_start, data_to_write);
    if (written < 0) {
        perror("write");
        send_error_response(client_socket, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error", "Failed to write to file.");
        return -1;
    }
    total_written += written;

    // Stream remaining data if necessary
    int file_complete = (boundary_in_data != NULL);
    char stream_buffer[BUFFER_SIZE];
    while (!file_complete && total_written < UPLOAD_MAX_FILE_SIZE) {
        ssize_t bytes_read_stream = recv(client_socket, stream_buffer, BUFFER_SIZE, 0);
        if (bytes_read_stream <= 0) break;
        
        boundary_in_data = memmem(stream_buffer, bytes_read_stream, data->boundary, strlen(data->boundary));
        data_to_write = bytes_read_stream;
        if (boundary_in_data) {
            data_to_write = boundary_in_data - stream_buffer - 2;
            file_complete = 1;
        }

        if (total_written + data_to_write > UPLOAD_MAX_FILE_SIZE) {
            send_error_response(client_socket, HTTP_STATUS_PAYLOAD_TOO_LARGE, "Payload Too Large", "File exceeds maximum size limit.");
            return -1;
        }
        
        written = write(fd, stream_buffer, data_to_write);
        if(written < 0) {
             perror("write");
             send_error_response(client_socket, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error", "Failed during file stream write.");
             return -1;
        }
        total_written += written;
    }
    return 0;
}

/**
 * @brief Atomically renames the temporary file and sets final permissions.
 * @return 0 on success, -1 on failure.
 */
int finalize_upload(const char *upload_dir, const char *temp_filepath, const char *final_filename, int client_socket) {
    char final_filepath[MAX_FILEPATH_LEN];
    snprintf(final_filepath, sizeof(final_filepath), "%s/%s", upload_dir, final_filename);
    
    if (rename(temp_filepath, final_filepath) != 0) {
        perror("rename");
        if (unlink(temp_filepath) != 0) {
             perror("unlink failed on temp file");
        }
        if (errno == EEXIST) {
            send_error_response(client_socket, HTTP_STATUS_CONFLICT, "Conflict", "File with that name already exists.");
        } else {
            send_error_response(client_socket, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error", "Could not save file.");
        }
        return -1;
    }
    
    chmod(final_filepath, S_IRUSR | S_IWUSR);
    return 0;
}

/**
 * @brief Drops root privileges and switches to a specified user.
 */
void drop_privileges(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        fprintf(stderr, "Fatal: Could not find user '%s' to drop privileges.\n", username);
        exit(1);
    }
    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        perror("setgid/setuid");
        exit(1);
    }
    if (getuid() == 0 || geteuid() == 0 || getgid() == 0 || getegid() == 0) {
        fprintf(stderr, "Fatal: Failed to drop privileges completely.\n");
        exit(1);
    }
}

/**
 * @brief Sanitizes a filename to prevent directory traversal and other attacks.
 */
void sanitize_filename(char *filename) {
    if (filename == NULL) return;
    char *p = filename;
    while (*p) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' && *p != '_') {
            *p = '_';
        }
        p++;
    }
}

/**
 * @brief Serves a static file to the client.
 */
void serve_file(int client_socket, const char *filename) {
    if (filename == NULL || strlen(filename) == 0) {
        send_error_response(client_socket, HTTP_STATUS_INTERNAL_SERVER_ERROR, "Internal Server Error", "Invalid filename.");
        return;
    }

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        send_error_response(client_socket, HTTP_STATUS_NOT_FOUND, "Not Found", "The requested file does not exist.");
        return;
    }

    struct stat st;
    fstat(fd, &st);
    off_t file_size = st.st_size;

    char header[MAX_HEADER_LEN];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n\r\n",
             get_content_type(filename), file_size);
    send(client_socket, header, strlen(header), 0);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        send(client_socket, buffer, bytes_read, 0);
    }
    close(fd);
}

/**
 * @brief Returns the MIME type for a given filename based on its extension.
 */
const char* get_content_type(const char* filename) {
    if (!filename || strlen(filename) == 0) return "application/octet-stream";
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "application/octet-stream";
    
    if (strcmp(dot, ".html") == 0) return "text/html";
    if (strcmp(dot, ".css") == 0) return "text/css";
    if (strcmp(dot, ".js") == 0) return "application/javascript";
    if (strcmp(dot, ".txt") == 0) return "text/plain";
    if (strcmp(dot, ".jpg") == 0) return "image/jpeg";
    if (strcmp(dot, ".png") == 0) return "image/png";
    
    return "application/octet-stream";
}

/**
 * @brief Sends a formatted HTTP error response to the client.
 */
void send_error_response(int client_socket, HTTPStatus status_code, const char *status_message, const char* body) {
    char response[MAX_HEADER_LEN];
    const char* body_to_use = body ? body : ""; // Use empty string if body is NULL
    snprintf(response, sizeof(response), 
             "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
             status_code, status_message, strlen(body_to_use), body_to_use);
    send(client_socket, response, strlen(response), 0);
}

