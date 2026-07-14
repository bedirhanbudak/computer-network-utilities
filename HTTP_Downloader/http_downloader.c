#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>

#define BUFFER_SIZE 8192

typedef struct
{
    int id;
    char *host;
    char *path;
    long start_range;
    long end_range;
    SSL_CTX *ctx;
} DownloadArgs;

// Partition Host and Path
void url_partition(const char *url, char **host, char **path)
{
    char *tmp = strdup(url);
    char *p = strstr(tmp, "://");
    if (p == NULL)
    {
        p = tmp;
    }
    else
    {
        p = p + 3;
    }
    char *slash = strchr(p, '/');
    if (slash != NULL)
    {
        *slash = '\0';
        *host = strdup(p);
        *path = strdup(slash + 1);
    }
    else
    {
        *host = strdup(p);
        *path = strdup("");
    }
    free(tmp);
}

// TCP Connection
int tcp_connection(const char *host)
{
    struct addrinfo hints, *servinfo, *p;
    int sock, rv;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, "443", &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // Connection to Address
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("socket");
            continue;
        }
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sock);
            perror("connect");
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    return sock;
}

// Non-blocking SSL Handshake
int ssl_handshake(SSL *ssl, int sock)
{
    int check;
    while (1)
    {
        check = SSL_connect(ssl);
        if (check == 1)
        {
            return 0;
        }

        int err = SSL_get_error(ssl, check);
        if (err == SSL_ERROR_WANT_READ)
        {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(sock, &read_fds);

            // Waiting for Data
            if (select(sock + 1, &read_fds, NULL, NULL, NULL) < 0)
            {
                perror("select (read)");
                return -1;
            }
        }
        else if (err == SSL_ERROR_WANT_WRITE)
        {
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(sock, &write_fds);

            // Waiting for Socket
            if (select(sock + 1, NULL, &write_fds, NULL, NULL) < 0)
            {
                perror("select (write)");
                return -1;
            }
        }
        else
        {
            fprintf(stderr, "SSL handshake error\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
}

// Getting the File Size
long get_size(const char *host, const char *path, SSL_CTX *ctx)
{
    int sock = tcp_connection(host);
    if (sock < 0)
        return -1;

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1)
    {
        fprintf(stderr, "SSL connection error!\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return -1;
    }

    char req[1024], response_buf[BUFFER_SIZE];

    // simplified
    snprintf(req, sizeof(req),
             "HEAD /%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: http_downloader/1.0 (BJ)\r\n"
             "Accept: */*\r\n"
             "Accept-Encoding: identity\r\n"
             "Connection: close\r\n\r\n",
             path, host);

    SSL_write(ssl, req, strlen(req));

    // read until the end
    int total = 0, n, header_done = 0;
    while ((n = SSL_read(ssl, response_buf + total, (int)sizeof(response_buf) - 1 - total)) > 0)
    {
        total += n;
        response_buf[total] = '\0';
        if (strstr(response_buf, "\r\n\r\n"))
        {
            header_done = 1;
            break;
        }
        if (total >= (int)sizeof(response_buf) - 1)
            break;
    }

    long size = -1;
    if (header_done)
    {
        char *cl_ptr = strcasestr(response_buf, "Content-Length:");
        if (cl_ptr)
        {
            if (sscanf(cl_ptr, "%*[^:]: %ld", &size) != 1)
                size = -1;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    return size;
}

// Downloading Parts
void *download_part(void *arg)
{
    DownloadArgs *args = (DownloadArgs *)arg;
    int sock = tcp_connection(args->host);
    if (sock < 0)
    {
        fprintf(stderr, "Thread %d: TCP connection failed!\n", args->id);
        return NULL;
    }

    SSL *ssl = SSL_new(args->ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, args->host);

    // Making Socket Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    if (ssl_handshake(ssl, sock) != 0)
    {
        fprintf(stderr, "Thread %d: SSL Handshake failed!\n", args->id);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    // Making Socket Blocking Again
    fcntl(sock, F_SETFL, flags);

    printf("Thread %d: Connection successful. Download range: %ld-%ld\n", args->id, args->start_range, args->end_range);

    char part_name[32];

    // changed to snprintf
    snprintf(part_name, sizeof(part_name), "part_%d", args->id);
    FILE *fp = fopen(part_name, "wb");
    if (!fp)
    {
        perror("Could not create part!");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    char req[1024];
    snprintf(req, sizeof(req),
             "GET /%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: http_downloader/1.0 (BJ)\r\n"
             "Accept: */*\r\n"
             "Range: bytes=%ld-%ld\r\n"
             "Accept-Encoding: identity\r\n"
             "Connection: close\r\n\r\n",
             args->path, args->host, args->start_range, args->end_range);
    SSL_write(ssl, req, strlen(req));

    // Writing the Content to the File
    char buffer[BUFFER_SIZE];
    int read;

    // wait until the end, then write body
    char header_buffer[8192];
    int header_length = 0, got_header = 0;

    while ((read = SSL_read(ssl, buffer, sizeof(buffer))) > 0)
    {
        if (!got_header)
        {
            // simplified
            int space = (int)sizeof(header_buffer) - header_length;
            int to_copy = read < space ? read : space;
            if (to_copy > 0)
            {
                memcpy(header_buffer + header_length, buffer, to_copy);
                header_length += to_copy;
            }

            char *sep = NULL;
            if (header_length >= 4)
                sep = strstr(header_buffer, "\r\n\r\n");
            if (sep)
            {
                got_header = 1;
                int header_bytes = (int)((sep + 4) - header_buffer);
                int body_in_accum = header_length - header_bytes;
                if (body_in_accum > 0)
                {
                    fwrite(header_buffer + header_bytes, 1, body_in_accum, fp);
                }
                if (to_copy < read)
                {
                    fwrite(buffer + to_copy, 1, read - to_copy, fp);
                }
            }
            else if (header_length == (int)sizeof(header_buffer))
            {
                fprintf(stderr, "Thread %d: response header too large.\n", args->id);
                fclose(fp);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sock);
                return NULL;
            }
        }
        else
        {
            fwrite(buffer, 1, read, fp);
        }
    }

    fclose(fp);
    printf("Thread %d: %s downloaded.\n", args->id, part_name);

    // release
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    return NULL;
}

// Merge Function
void merge_files(int num, const char *output)
{
    FILE *out_fp = fopen(output, "wb");

    if (!out_fp)
    {
        perror("Could not open the output file!");
        return;
    }
    printf("Files are combining (%s)\n", output);
    char buffer[BUFFER_SIZE];
    for (int i = 1; i <= num; i++)
    {
        char part_name[32];
        snprintf(part_name, sizeof(part_name), "part_%d", i);
        FILE *fp = fopen(part_name, "rb");
        if (!fp)
        {
            fprintf(stderr, "Warning: %s could not read, skipping.\n", part_name);
            continue;
        }
        size_t rsz;
        while ((rsz = fread(buffer, 1, BUFFER_SIZE, fp)) > 0)
        {
            fwrite(buffer, 1, rsz, out_fp);
        }
        fclose(fp);
    }
    fclose(out_fp);
    printf("Combination successful.\n");
}


int main(int argc, char *argv[])
{
    char *url = NULL;
    int num = 0;
    char *output = NULL;

    if (argc != 7)
    {
        fprintf(stderr, "Usage: %s -u HTTPS_URL -n NUM_PARTS -o OUTPUT_FILE\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i < argc; i += 2)
    {
        if (strcmp(argv[i], "-u") == 0)
            url = argv[i + 1];
        else if (strcmp(argv[i], "-n") == 0)
            num = atoi(argv[i + 1]);
        else if (strcmp(argv[i], "-o") == 0)
            output = argv[i + 1];
    }

    // Starting SSL
    SSL_library_init();
    SSL_load_error_strings();

    char *host = NULL;
    char *path = NULL;
    url_partition(url, &host, &path);

    // Creating SSL Context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        fprintf(stderr, "SSL Context failed!.\n");
        exit(EXIT_FAILURE);
    }

    // Verifying CA
    if (!SSL_CTX_set_default_verify_paths(ctx))
    {
        fprintf(stderr, "CA certificates could not be loaded!\n");
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    long total_size = get_size(host, path, ctx);
    if (total_size <= 0)
    {
        fprintf(stderr, "File size is unknown or 0.\n");
        exit(EXIT_FAILURE);
    }
    printf("Total File Size: %ld bytes\n", total_size);

    long part_size = total_size / num;

    pthread_t threads[num];
    DownloadArgs args[num];

    for (int i = 0; i < num; i++)
    {
        args[i].id = i + 1;
        args[i].host = host;
        args[i].path = path;
        args[i].ctx = ctx;
        args[i].start_range = i * part_size;
        args[i].end_range = (i == num - 1) ? total_size - 1 : (i * part_size) + part_size - 1;
        pthread_create(&threads[i], NULL, download_part, &args[i]);
    }

    for (int i = 0; i < num; i++)
    {
        pthread_join(threads[i], NULL);
    }

    merge_files(num, output);

    // clean
    free(host);
    free(path);
    SSL_CTX_free(ctx);

    return 0;
}