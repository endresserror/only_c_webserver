#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <limits.h>
#include <cjson/cJSON.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define BASE_DIRECTORY "/var/www"

void *handle_connection(void *socket_desc);
void execute_cgi(int client_socket, const char *path);
void send_file(int client_socket, const char *path);
int validate_token_with_auth_server(const char *token);

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t thread_id;
    int opt = 1;

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d...\n", PORT);

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue; // Accept failure should not terminate the server
        }

        int *new_sock = malloc(sizeof(int));
        if (new_sock == NULL) {
            perror("malloc failed");
            close(new_socket);
            continue;
        }

        *new_sock = new_socket;

        if (pthread_create(&thread_id, NULL, handle_connection, (void*) new_sock) < 0) {
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

    char buffer[BUFFER_SIZE] = {0};
    char method[10], path[256], protocol[10];
    ssize_t valread;

    valread = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (valread <= 0) {
        close(client_socket);
        pthread_exit(NULL);
    }
    buffer[valread] = '\0';

    printf("Received request:\n%s\n", buffer);

    // HTTPリクエスト解析
    char *saveptr;
    char *line = strtok_r(buffer, "\r\n", &saveptr);
    if (line == NULL || sscanf(line, "%9s %255s %9s", method, path, protocol) != 3) {
        char *response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        write(client_socket, response, strlen(response));
        close(client_socket);
        pthread_exit(NULL);
    }

    if (strstr(path, "..") != NULL) {
        char *response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        write(client_socket, response, strlen(response));
        close(client_socket);
        pthread_exit(NULL);
    }

    printf("Method: %s, Path: %s, Protocol: %s\n", method, path, protocol);

    if (strcmp(method, "GET") == 0) {
        char real_path[PATH_MAX];
        snprintf(real_path, sizeof(real_path), "%s%s", BASE_DIRECTORY, path);
        if (realpath(real_path, real_path) == NULL || strncmp(real_path, BASE_DIRECTORY, strlen(BASE_DIRECTORY)) != 0) {
            char *response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            write(client_socket, response, strlen(response));
        } else {
            send_file(client_socket, real_path);
        }
    } else {
        char *response = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n";
        write(client_socket, response, strlen(response));
    }

    close(client_socket);
    pthread_exit(NULL);
}

void send_file(int client_socket, const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        char *response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        write(client_socket, response, strlen(response));
        return;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    dprintf(client_socket, "HTTP/1.1 200 OK\r\n");
    dprintf(client_socket, "Content-Length: %ld\r\n", file_size);
    dprintf(client_socket, "Content-Type: text/html; charset=UTF-8\r\n");
    dprintf(client_socket, "\r\n");

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        write(client_socket, buffer, bytes_read);
    }

    fclose(fp);
}

int validate_token_with_auth_server(const char *token) {
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
}
