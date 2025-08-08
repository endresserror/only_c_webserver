#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <limits.h>
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_CJSON
#include <cjson/cJSON.h>
#endif

#define PORT 8080
#define BUFFER_SIZE 4096
#define BASE_DIRECTORY "/var/www"
#define MAX_PATH_LENGTH 2048
#define MAX_CONNECTIONS_PER_IP 10
#define RATE_LIMIT_WINDOW 60
#define MAX_REQUESTS_PER_WINDOW 100
#define MAX_HEADER_SIZE 8192
#define MAX_POST_SIZE 1048576

typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t first_request;
    int request_count;
    int connection_count;
} client_info_t;

typedef struct {
    client_info_t clients[1000];
    int client_count;
    pthread_mutex_t mutex;
} rate_limiter_t;

void *handle_connection(void *socket_desc);
void execute_cgi(int client_socket, const char *path);
void send_file(int client_socket, const char *path);
int validate_token_with_auth_server(const char *token);
void log_security_event(const char *event, const char *client_ip, const char *details);
int check_rate_limit(const char *client_ip);
void cleanup_old_clients(void);
void send_security_headers(int client_socket);
int validate_request_headers(const char *headers);
void send_error_response(int client_socket, int status_code, const char *message);
char* get_mime_type(const char *filename);
int is_safe_path(const char *path);
void handle_post_request(int client_socket, const char *path, const char *body, size_t body_len);

rate_limiter_t rate_limiter = {.client_count = 0, .mutex = PTHREAD_MUTEX_INITIALIZER};

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t thread_id;
    int opt = 1;

    openlog("webserver", LOG_PID | LOG_CONS, LOG_DAEMON);
    log_security_event("SERVER_START", "localhost", "Web server starting up");

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_security_event("SOCKET_ERROR", "localhost", "Failed to create socket");
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        log_security_event("SOCKET_ERROR", "localhost", "Failed to set socket options");
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_security_event("BIND_ERROR", "localhost", "Failed to bind socket");
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        log_security_event("LISTEN_ERROR", "localhost", "Failed to listen on socket");
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Secure web server listening on port %d...\n", PORT);
    log_security_event("SERVER_READY", "localhost", "Web server ready to accept connections");

    while (1) {
        cleanup_old_clients();
        
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            log_security_event("ACCEPT_ERROR", "unknown", "Failed to accept connection");
            perror("accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);

        if (!check_rate_limit(client_ip)) {
            log_security_event("RATE_LIMIT_EXCEEDED", client_ip, "Rate limit exceeded");
            send_error_response(new_socket, 429, "Too Many Requests");
            close(new_socket);
            continue;
        }

        int *new_sock = malloc(sizeof(int));
        if (new_sock == NULL) {
            log_security_event("MEMORY_ERROR", client_ip, "Failed to allocate memory for connection");
            perror("malloc failed");
            close(new_socket);
            continue;
        }

        *new_sock = new_socket;

        if (pthread_create(&thread_id, NULL, handle_connection, (void*) new_sock) < 0) {
            log_security_event("THREAD_ERROR", client_ip, "Failed to create thread");
            perror("could not create thread");
            free(new_sock);
            close(new_socket);
            continue;
        }

        pthread_detach(thread_id);
    }

    return 0;
}

void *handle_connection(void *socket_desc) {
    int client_socket = *(int*)socket_desc;
    free(socket_desc);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char client_ip[INET_ADDRSTRLEN] = "unknown";
    
    if (getpeername(client_socket, (struct sockaddr*)&client_addr, &client_len) == 0) {
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }

    char *buffer = malloc(MAX_HEADER_SIZE);
    if (!buffer) {
        log_security_event("MEMORY_ERROR", client_ip, "Failed to allocate request buffer");
        close(client_socket);
        pthread_exit(NULL);
    }

    char method[16], path[MAX_PATH_LENGTH], protocol[16];
    ssize_t total_read = 0;
    ssize_t valread;

    while (total_read < MAX_HEADER_SIZE - 1) {
        valread = read(client_socket, buffer + total_read, MAX_HEADER_SIZE - 1 - total_read);
        if (valread <= 0) break;
        total_read += valread;
        buffer[total_read] = '\0';
        if (strstr(buffer, "\r\n\r\n")) break;
    }

    if (total_read <= 0) {
        log_security_event("EMPTY_REQUEST", client_ip, "Empty or invalid request");
        free(buffer);
        close(client_socket);
        pthread_exit(NULL);
    }

    if (!validate_request_headers(buffer)) {
        log_security_event("INVALID_HEADERS", client_ip, "Invalid or suspicious headers");
        send_error_response(client_socket, 400, "Bad Request");
        free(buffer);
        close(client_socket);
        pthread_exit(NULL);
    }

    char *saveptr;
    char *line = strtok_r(buffer, "\r\n", &saveptr);
    if (line == NULL || sscanf(line, "%15s %2047s %15s", method, path, protocol) != 3) {
        log_security_event("MALFORMED_REQUEST", client_ip, "Malformed HTTP request line");
        send_error_response(client_socket, 400, "Bad Request");
        free(buffer);
        close(client_socket);
        pthread_exit(NULL);
    }

    if (!is_safe_path(path)) {
        log_security_event("PATH_TRAVERSAL_ATTEMPT", client_ip, path);
        send_error_response(client_socket, 403, "Forbidden");
        free(buffer);
        close(client_socket);
        pthread_exit(NULL);
    }

    log_security_event("REQUEST", client_ip, method);

    send_security_headers(client_socket);

    if (strcmp(method, "GET") == 0) {
        char real_path[PATH_MAX];
        char resolved_path[PATH_MAX];
        snprintf(real_path, sizeof(real_path), "%s%s", BASE_DIRECTORY, path);
        if (realpath(real_path, resolved_path) == NULL || strncmp(resolved_path, BASE_DIRECTORY, strlen(BASE_DIRECTORY)) != 0) {
            log_security_event("ACCESS_DENIED", client_ip, path);
            send_error_response(client_socket, 403, "Forbidden");
        } else {
            send_file(client_socket, resolved_path);
        }
    } else if (strcmp(method, "POST") == 0) {
        char *body_start = strstr(buffer, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            size_t body_len = total_read - (body_start - buffer);
            handle_post_request(client_socket, path, body_start, body_len);
        } else {
            send_error_response(client_socket, 400, "Bad Request");
        }
    } else {
        log_security_event("UNSUPPORTED_METHOD", client_ip, method);
        send_error_response(client_socket, 501, "Not Implemented");
    }

    free(buffer);
    close(client_socket);
    pthread_exit(NULL);
}

void send_file(int client_socket, const char *path) {
    struct stat file_stat;
    if (stat(path, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
        send_error_response(client_socket, 404, "Not Found");
        return;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        send_error_response(client_socket, 404, "Not Found");
        return;
    }

    char *mime_type = get_mime_type(path);
    
    dprintf(client_socket, "HTTP/1.1 200 OK\r\n");
    dprintf(client_socket, "Content-Length: %ld\r\n", file_stat.st_size);
    dprintf(client_socket, "Content-Type: %s\r\n", mime_type);
    dprintf(client_socket, "Cache-Control: no-cache, no-store, must-revalidate\r\n");
    dprintf(client_socket, "X-Content-Type-Options: nosniff\r\n");
    dprintf(client_socket, "X-Frame-Options: DENY\r\n");
    dprintf(client_socket, "X-XSS-Protection: 1; mode=block\r\n");
    dprintf(client_socket, "Content-Security-Policy: default-src 'self'\r\n");
    dprintf(client_socket, "\r\n");

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        if (write(client_socket, buffer, bytes_read) != (ssize_t)bytes_read) {
            break;
        }
    }

    fclose(fp);
    free(mime_type);
}

int validate_token_with_auth_server(const char *token) {
#ifdef HAVE_CJSON
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8081);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return 0;
    }

    char request[BUFFER_SIZE];
    snprintf(request, sizeof(request), 
        "GET /validate?token=%s HTTP/1.1\r\nHost: localhost:8081\r\nConnection: close\r\n\r\n", token);
    send(sock, request, strlen(request), 0);

    char response[8192] = {0};
    read(sock, response, sizeof(response) - 1);
    close(sock);

    char *body = strstr(response, "\r\n\r\n");
    if (!body) return 0;
    body += 4;

    cJSON *json = cJSON_Parse(body);
    if (!json) return 0;

    cJSON *success = cJSON_GetObjectItem(json, "success");
    int result = cJSON_IsTrue(success);

    cJSON_Delete(json);
    return result;
#else
    (void)token;
    return 0;
#endif
}

void log_security_event(const char *event, const char *client_ip, const char *details) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    
    syslog(LOG_INFO, "[%s] %s from %s: %s", time_str, event, client_ip, details);
    printf("[%s] %s from %s: %s\n", time_str, event, client_ip, details);
}

int check_rate_limit(const char *client_ip) {
    pthread_mutex_lock(&rate_limiter.mutex);
    
    time_t now = time(NULL);
    int found = -1;
    
    for (int i = 0; i < rate_limiter.client_count; i++) {
        if (strcmp(rate_limiter.clients[i].ip, client_ip) == 0) {
            found = i;
            break;
        }
    }
    
    if (found == -1) {
        if (rate_limiter.client_count < 1000) {
            found = rate_limiter.client_count++;
            strcpy(rate_limiter.clients[found].ip, client_ip);
            rate_limiter.clients[found].first_request = now;
            rate_limiter.clients[found].request_count = 1;
            rate_limiter.clients[found].connection_count = 1;
        } else {
            pthread_mutex_unlock(&rate_limiter.mutex);
            return 0;
        }
    } else {
        if (now - rate_limiter.clients[found].first_request > RATE_LIMIT_WINDOW) {
            rate_limiter.clients[found].first_request = now;
            rate_limiter.clients[found].request_count = 1;
        } else {
            rate_limiter.clients[found].request_count++;
            if (rate_limiter.clients[found].request_count > MAX_REQUESTS_PER_WINDOW ||
                rate_limiter.clients[found].connection_count > MAX_CONNECTIONS_PER_IP) {
                pthread_mutex_unlock(&rate_limiter.mutex);
                return 0;
            }
        }
        rate_limiter.clients[found].connection_count++;
    }
    
    pthread_mutex_unlock(&rate_limiter.mutex);
    return 1;
}

void cleanup_old_clients(void) {
    static time_t last_cleanup = 0;
    time_t now = time(NULL);
    
    if (now - last_cleanup < 300) return;
    last_cleanup = now;
    
    pthread_mutex_lock(&rate_limiter.mutex);
    
    for (int i = 0; i < rate_limiter.client_count; i++) {
        if (now - rate_limiter.clients[i].first_request > RATE_LIMIT_WINDOW * 2) {
            memmove(&rate_limiter.clients[i], &rate_limiter.clients[i + 1], 
                    (rate_limiter.client_count - i - 1) * sizeof(client_info_t));
            rate_limiter.client_count--;
            i--;
        }
    }
    
    pthread_mutex_unlock(&rate_limiter.mutex);
}

void send_security_headers(int client_socket) {
    dprintf(client_socket, "X-Content-Type-Options: nosniff\r\n");
    dprintf(client_socket, "X-Frame-Options: DENY\r\n");
    dprintf(client_socket, "X-XSS-Protection: 1; mode=block\r\n");
    dprintf(client_socket, "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n");
    dprintf(client_socket, "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\r\n");
    dprintf(client_socket, "Referrer-Policy: strict-origin-when-cross-origin\r\n");
}

int validate_request_headers(const char *headers) {
    if (strlen(headers) > MAX_HEADER_SIZE) return 0;
    
    if (strstr(headers, "\r\n\r\n") == NULL) return 0;
    
    if (strstr(headers, "<script") || strstr(headers, "javascript:") || 
        strstr(headers, "vbscript:") || strstr(headers, "onload=") ||
        strstr(headers, "onerror=")) {
        return 0;
    }
    
    char *line = strtok((char*)headers, "\r\n");
    while (line != NULL) {
        if (strlen(line) > 4096) return 0;
        line = strtok(NULL, "\r\n");
    }
    
    return 1;
}

void send_error_response(int client_socket, int status_code, const char *message) {
    const char *status_text;
    switch (status_code) {
        case 400: status_text = "Bad Request"; break;
        case 403: status_text = "Forbidden"; break;
        case 404: status_text = "Not Found"; break;
        case 429: status_text = "Too Many Requests"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 501: status_text = "Not Implemented"; break;
        default: status_text = "Error"; break;
    }
    
    char response[512];
    int content_len = snprintf(response, sizeof(response), 
        "<html><body><h1>%d %s</h1><p>%s</p></body></html>", 
        status_code, status_text, message);
    
    dprintf(client_socket, "HTTP/1.1 %d %s\r\n", status_code, status_text);
    dprintf(client_socket, "Content-Type: text/html\r\n");
    dprintf(client_socket, "Content-Length: %d\r\n", content_len);
    send_security_headers(client_socket);
    dprintf(client_socket, "\r\n");
    if (write(client_socket, response, content_len) < 0) {
        perror("Failed to write error response");
    }
}

char* get_mime_type(const char *filename) {
    const char *ext = strrchr(filename, '.');
    char *mime_type = malloc(64);
    
    if (!ext) {
        strcpy(mime_type, "application/octet-stream");
    } else if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) {
        strcpy(mime_type, "text/html; charset=UTF-8");
    } else if (strcmp(ext, ".css") == 0) {
        strcpy(mime_type, "text/css");
    } else if (strcmp(ext, ".js") == 0) {
        strcpy(mime_type, "application/javascript");
    } else if (strcmp(ext, ".json") == 0) {
        strcpy(mime_type, "application/json");
    } else if (strcmp(ext, ".png") == 0) {
        strcpy(mime_type, "image/png");
    } else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) {
        strcpy(mime_type, "image/jpeg");
    } else if (strcmp(ext, ".gif") == 0) {
        strcpy(mime_type, "image/gif");
    } else if (strcmp(ext, ".txt") == 0) {
        strcpy(mime_type, "text/plain; charset=UTF-8");
    } else {
        strcpy(mime_type, "application/octet-stream");
    }
    
    return mime_type;
}

int is_safe_path(const char *path) {
    if (strstr(path, "..") != NULL) return 0;
    if (strstr(path, "//") != NULL) return 0;
    if (strstr(path, "\\") != NULL) return 0;
    if (path[0] != '/') return 0;
    if (strlen(path) >= MAX_PATH_LENGTH) return 0;
    
    for (int i = 0; path[i]; i++) {
        if ((unsigned char)path[i] < 32 && path[i] != '\t') return 0;
        if (path[i] == '<' || path[i] == '>' || path[i] == '"' || 
            path[i] == '|' || path[i] == '*' || path[i] == '?') return 0;
    }
    
    return 1;
}

void handle_post_request(int client_socket, const char *path, const char *body, size_t body_len) {
    if (body_len > MAX_POST_SIZE) {
        log_security_event("POST_TOO_LARGE", "client", path);
        send_error_response(client_socket, 413, "Payload Too Large");
        return;
    }
    
    if (strcmp(path, "/api/data") == 0) {
#ifdef HAVE_CJSON
        cJSON *json = cJSON_Parse(body);
        if (json == NULL) {
            send_error_response(client_socket, 400, "Invalid JSON");
            return;
        }
        
        dprintf(client_socket, "HTTP/1.1 200 OK\r\n");
        dprintf(client_socket, "Content-Type: application/json\r\n");
        send_security_headers(client_socket);
        dprintf(client_socket, "\r\n");
        dprintf(client_socket, "{\"status\":\"success\",\"message\":\"Data received\"}\r\n");
        
        cJSON_Delete(json);
#else
        (void)body;
        dprintf(client_socket, "HTTP/1.1 200 OK\r\n");
        dprintf(client_socket, "Content-Type: application/json\r\n");
        send_security_headers(client_socket);
        dprintf(client_socket, "\r\n");
        dprintf(client_socket, "{\"status\":\"success\",\"message\":\"Data received (JSON parsing unavailable)\"}\r\n");
#endif
    } else {
        send_error_response(client_socket, 404, "Not Found");
    }
}
