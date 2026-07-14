#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <getopt.h>

#define BUFFER_SIZE 4096

char deny_list[512][512];
int count_deny = 0;

static int use_doh = 0;
static char ip_doh[64] = "";
static char dst_udp_ip[64] = "";
static char denied_path[512] = "";
static char log_path[512] = "";
static FILE *fp = NULL;
static int Lport = 53;
static char bind_ip[64] = "127.0.0.1";

static const char *B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


// name checker
static void check_name(char *s)
{
    if (!s)
        return;

    int i = (int)strlen(s) - 1;
    while (i >= 0 && (s[i] == '\n' || s[i] == '\r' || isspace((unsigned char)s[i])))
        s[i--] = 0;
    size_t n = strlen(s);
    
    if (n > 0 && s[n - 1] == '.')
        s[n - 1] = 0;

    for (char *p = s; *p; ++p)
        *p = (char)tolower((unsigned char)*p);
}

// Load Denied List
void load_list(char *filename)
{
    FILE *f = fopen(filename, "r");
    if (!f)
    {
        return;
    }

    count_deny = 0;
    while (fgets(deny_list[count_deny], sizeof(deny_list[count_deny]), f))
    {
        deny_list[count_deny][strcspn(deny_list[count_deny], "\n")] = '\0';
        check_name(deny_list[count_deny]);
        if (deny_list[count_deny][0] != '\0')
        {
            count_deny++;
            if (count_deny >= 512)
                break;
        }
    }
    fclose(f);
    printf("%d addresses loaded from deny list.\n", count_deny);
}

// parse qname
static int parse_qname(const unsigned char *pkt, int len, int offset, char *out, int outsz)
{
    int p = offset, pos = 0;
    if (p >= len)
    {
        if (out && outsz > 0)
            out[0] = 0;
        return -1;
    }
    while (p < len)
    {
        uint8_t l = pkt[p++];
        if (l == 0)
            break;
        if (l > 63 || p + l > len)
        {
            if (out && outsz > 0)
                out[0] = 0;
            return -1;
        }
        if (pos && pos < outsz - 1)
            out[pos++] = '.';
        for (int i = 0; i < l && pos < outsz - 1; ++i)
            out[pos++] = (char)pkt[p++];
    }
    if (out && outsz > 0)
        out[pos] = 0;
    return p;
}

// Check Denied Domains
int is_denied(const char *domain)
{
    for (int i = 0; i < count_deny; i++)
    {
        if (strcmp(domain, deny_list[i]) == 0)
            return 1;
    }
    return 0;
}

// NXDOMAIN Reply
void nxdomain_reply(int sock, struct sockaddr_in *client, socklen_t clen, const unsigned char *req, int r_len)
{
    if (r_len < 2)
    {
        unsigned char msg[12] = {0};
        msg[2] = 0x81;
        msg[3] = 0x83;
        sendto(sock, msg, sizeof(msg), 0, (struct sockaddr *)client, clen);
        return;
    }

    unsigned char out[512];
    memset(out, 0, sizeof(out));

    // TxID
    out[0] = req[0];
    out[1] = req[1];

    // Flags: QR=1 / RD inherit / RA=1 / RCODE=3
    unsigned char rd = (req[2] & 0x01);
    out[2] = 0x80 | rd;
    out[3] = 0x83;

    if (r_len >= 6)
    {
        out[4] = req[4];
        out[5] = req[5];
    }

    // parse question
    int q = parse_qname(req, r_len, 12, (char[1]){0}, 1);
    int q_len = 0;
    if (q > 0 && q + 4 <= r_len)
        q_len = (q + 4) - 12;
    else
    {
        int p = 12, lim = r_len;
        while (p < lim && req[p] != 0x00)
        {
            uint8_t l = req[p];
            if (l == 0 || l > 63 || p + 1 + l > lim)
            {
                p = lim;
                break;
            }
            p += 1 + l;
        }
        if (p < lim && req[p] == 0x00 && p + 4 < lim)
            q_len = (p + 1 + 4) - 12;
    }

    // find OPT
    int opt_len = 0;
    const unsigned char *opt_ptr = NULL;
    if (q_len > 0)
    {
        int p = 12 + q_len;
        if (p + 11 <= r_len && req[p] == 0x00 && req[p + 1] == 0x00 && req[p + 2] == 0x29)
        {
            int rdlen = (req[p + 9] << 8) | req[p + 10];
            int total = 11 + rdlen;
            if (p + total <= r_len)
            {
                opt_ptr = &req[p];
                opt_len = total;
            }
        }
    }

    int w = 12;
    if (q_len > 0)
    {
        memcpy(out + w, req + 12, q_len);
        w += q_len;
    }
    if (opt_len > 0 && w + opt_len <= (int)sizeof(out))
    {
        memcpy(out + w, opt_ptr, opt_len);
        w += opt_len;
    }

    sendto(sock, out, w, 0, (struct sockaddr *)client, clen);
}

// Curl Callback
size_t curl_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
    struct Buf
    {
        unsigned char *buf;
        size_t cap;
        size_t len;
    } *B = (struct Buf *)data;
    
    size_t n = size * nmemb;
    if (B->len + n > B->cap)
        n = B->cap - B->len;
    memcpy(B->buf + B->len, ptr, n);
    B->len += n;
    return n;
}

// base64 encode
static int base64_encode(const unsigned char *in, int len, char *out, int outsz)
{
    char *p = out;
    for (int i = 0; i < len; i += 3)
    {
        uint32_t v = in[i] << 16;
        if (i + 1 < len)
            v |= in[i + 1] << 8;
        if (i + 2 < len)
            v |= in[i + 2];

        if (p - out + 4 >= outsz)
            return -1;

        *p++ = B64[(v >> 18) & 63];
        *p++ = B64[(v >> 12) & 63];

        if (i + 1 < len)
            *p++ = B64[(v >> 6) & 63];
        else
            *p++ = '=';

        if (i + 2 < len)
            *p++ = B64[v & 63];
        else
            *p++ = '=';
    }

    *p = '\0';
    for (char *q = out; *q; ++q)
    {
        if (*q == '+')
            *q = '-';
        else if (*q == '/')
            *q = '_';
    }
    while (p > out && *(p - 1) == '=')
        --p;
    *p = '\0';
    return (int)(p - out);
}

// DoH Query Forwarder
int doh_forward(const unsigned char *dns_q, int q_len, unsigned char *response, int rcap, const char *doh_ip, int *out_len)
{
    char b64url[4096];
    if (base64_encode(dns_q, q_len, b64url, sizeof(b64url)) < 0)
        return 0;

    char url[4600];
    snprintf(url, sizeof(url), "https://%s/dns-query?dns=%s", doh_ip, b64url);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/dns-message");

    struct Buf
    {
        unsigned char *buf;
        size_t cap;
        size_t len;
    } B = {response, (size_t)rcap, 0};

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        curl_slist_free_all(headers);
        return 0;
    }

    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &B);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    int success = (res == CURLE_OK) && (http_code >= 200 && http_code < 300) && (B.len >= 12);
    if (success)
        *out_len = (int)B.len;

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return success;
}

// UDP upstream forward
int udp_forward(const unsigned char *dns_q, int q_len, unsigned char *response, int rcap, const char *upstream_ip, uint16_t upstream_port, int timeout_ms, int *out_len)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in svr;
    memset(&svr, 0, sizeof(svr));
    svr.sin_family = AF_INET;
    svr.sin_port = htons(upstream_port);
    svr.sin_addr.s_addr = inet_addr(upstream_ip);

    ssize_t n = sendto(fd, dns_q, q_len, 0, (struct sockaddr *)&svr, sizeof(svr));
    if (n != q_len)
    {
        close(fd);
        return 0;
    }

    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    ssize_t r = recvfrom(fd, response, rcap, 0, (struct sockaddr *)&from, &fl);
    int success = 0;
    if (r > 0) {
        *out_len = (int)r;
        success = 1;
    }
    close(fd);
    return success; 
}

// Qtype names
static const char *qtype_name(uint16_t t)
{
    switch (t)
    {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 255: return "ANY";
        default: return NULL;
    }
}

// Logging
void write_log(const char *domain, const char *qtype, const char *result)
{
    if (!fp)
        return;
    fprintf(fp, "%s %s %s\n", domain, qtype, result);
    fflush(fp);
}

// Main Query
void main_query(int sock, unsigned char *buffer, int recv_len, struct sockaddr_in *client, socklen_t clen, const char *mode_ip, int use_doh_flag)
{
    char domain[256] = {0};
    int qoff = parse_qname(buffer, recv_len, 12, domain, sizeof(domain));
    check_name(domain);

    char qtype_str[16] = "?";
    uint16_t qtype = 0;
    if (qoff > 0 && qoff + 2 <= recv_len)
    {
        qtype = ((uint8_t)buffer[qoff] << 8) | (uint8_t)buffer[qoff + 1];
        const char *qs = qtype_name(qtype);
        if (qs)
            strncpy(qtype_str, qs, sizeof(qtype_str) - 1);
        else
            snprintf(qtype_str, sizeof(qtype_str), "%u", qtype);
    }

    char ip_str[INET_ADDRSTRLEN] = "-";
    inet_ntop(AF_INET, &(client->sin_addr), ip_str, sizeof(ip_str));
    if (domain[0])
        printf("Query: %s from %s\n", domain, ip_str);
    else
        printf("Query: (unknown) from %s\n", ip_str);

    if (domain[0] && is_denied(domain))
    {
        printf("Blocked: %s\n", domain);
        write_log(domain, qtype_str, (char *)"DENY");
        nxdomain_reply(sock, client, clen, buffer, recv_len);
        return;
    }

    unsigned char response[BUFFER_SIZE] = {0};
    int resp_len = 0, success = 0;

    if (use_doh_flag)
    {
        success = doh_forward(buffer, recv_len, response, sizeof(response), mode_ip, &resp_len);
    }
    else
    {
        success = udp_forward(buffer, recv_len, response, sizeof(response), mode_ip, 53, 2000, &resp_len);
    }

    if (success && resp_len >= 12)
    {
        printf("Forwarded: %s via %s\n", domain[0] ? domain : "(unknown)", use_doh_flag ? "DoH" : "UDP");
        if (domain[0])
            write_log(domain, qtype_str, (char *)"ALLOW");
        else
            write_log((char *)"-", qtype_str, (char *)"ALLOW");
        sendto(sock, response, resp_len, 0, (struct sockaddr *)client, clen);
    }
    else
    {
        if (domain[0])
            printf("Failed: %s\n", domain);
        else
            printf("Failed: (unknown)\n");
        if (domain[0])
            write_log(domain, qtype_str, (char *)"FAILED");
        else
            write_log((char *)"-", qtype_str, (char *)"FAILED");
        nxdomain_reply(sock, client, clen, buffer, recv_len);
    }
}


// Start DNS
void start_dns(const char *mode_ip, int use_doh_flag)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        exit(1);
    }

    struct sockaddr_in serv, client;
    socklen_t clen = sizeof(client);
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    
    // last update (J): ip address is getting from parameter
    inet_pton(AF_INET, bind_ip, &serv.sin_addr);
    serv.sin_port = htons(Lport);

    if (bind(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0)
    {
        close(sock);
        exit(1);
    }

    char addrbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &serv.sin_addr, addrbuf, sizeof(addrbuf));
    printf("DNS Forwarder is running on %s:%d (Upstream: %s via %s)\n", addrbuf, Lport, mode_ip, use_doh_flag ? "DoH" : "UDP");

    unsigned char buffer[BUFFER_SIZE];
    while (1)
    {
        int recv_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client, &clen);
        if (recv_len > 0)
            main_query(sock, buffer, recv_len, &client, clen, mode_ip, use_doh_flag);
    }
}

// Usage Info
static void usage(const char *prog)
{
    printf(
        "usage: %s [-h] [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [-p PORT] [-b BIND_IP] [--doh] [--doh_server DOH_SERVER]\n\n"
        "optional parameters:\n"
        "-h, --help                 Show this help message and exit\n"
        "-d DST_IP                  Destination DNS server IP (UDP mode)\n"
        "-f DENY_LIST_FILE          File containing domains to block\n"
        "-l LOG_FILE                Append-only log file\n"
        "-p PORT                    Local UDP port to bind (default: 53)\n"
        "-b BIND_IP                 Local IP address to bind (default: 127.0.0.1)\n"
        "--doh                      Use default upstream DoH server\n"
        "--doh_server DOH_SERVER    Use this upstream DoH server\n",
        prog);
}


int main(int argc, char *argv[])
{
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'h'},
        {"doh", no_argument, 0, 1},
        {"doh_server", required_argument, 0, 2},
        {"port", required_argument, 0, 'p'},
        {"bind_ip", required_argument, 0, 'b'},
        {0, 0, 0, 0}};

    int opt, longidx;
    while ((opt = getopt_long(argc, argv, "hd:f:l:p:b:", long_opts, &longidx)) != -1)
    {
        switch (opt)
        {
        case 'h':
            usage(argv[0]);
            return 0;
        case 'd':
            strncpy(dst_udp_ip, optarg, sizeof(dst_udp_ip) - 1);
            break;
        case 'f':
            strncpy(denied_path, optarg, sizeof(denied_path) - 1);
            break;
        case 'l':
            strncpy(log_path, optarg, sizeof(log_path) - 1);
            break;
        case 'p':
            Lport = atoi(optarg);
            if (Lport <= 0) Lport = 53;
            break;
        case 'b':
            strncpy(bind_ip, optarg, sizeof(bind_ip) - 1);
            break;
        case 1:
            use_doh = 1;
            break;
        case 2:
            use_doh = 1;
            strncpy(ip_doh, optarg, sizeof(ip_doh) - 1);
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    // Validation
    if (denied_path[0] == '\0')
    {
        fprintf(stderr, "Error: -f DENY_LIST_FILE is required.\n");
        usage(argv[0]);
        return 1;
    }
    if (!use_doh && dst_udp_ip[0] == '\0')
    {
        fprintf(stderr, "Error: -d DST_IP is required when DoH is not used.\n");
        usage(argv[0]);
        return 1;
    }
    if (use_doh && ip_doh[0] == '\0')
    {
        strncpy(ip_doh, "1.1.1.1", sizeof(ip_doh) - 1);
    }

    // log
    if (log_path[0])
    {
        fp = fopen(log_path, "a");
        if (!fp)
        {
            return 1;
        }
    }

    load_list(denied_path);

    // start server
    if (use_doh)
        start_dns(ip_doh, 1);
    else
        start_dns(dst_udp_ip, 0);

    if (fp)
        fclose(fp);
    return 0;
}