#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

typedef struct {
    SSL_CTX *ctx;
    int ssl_enabled;
    char cert_file[256];
    char key_file[256];
    int ssl_port;
} ssl_config_t;

int init_ssl(void);
void cleanup_ssl(void);
SSL_CTX* create_ssl_context(void);
int configure_ssl_context(SSL_CTX *ctx, const char *cert_file, const char *key_file);
int handle_ssl_connection(int client_socket, SSL_CTX *ctx);

#endif