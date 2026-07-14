#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#define VM_IP "192.168.1.16"

// IP Checksum
unsigned short ip_checksum(void *b, int length)
{
    unsigned short *buffer = b;
    unsigned int sum = 0;

    while (length > 1) {
        sum += *buffer++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(unsigned char *)buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

// TCP Checksum
unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int tcp_len)
{
    int psize = 12 + tcp_len;
    unsigned char *pseudo = malloc(psize);
    if (!pseudo)
        exit(1);

    memset(pseudo, 0, psize);
    memcpy(pseudo + 0, &ip->saddr, 4);
    memcpy(pseudo + 4, &ip->daddr, 4);

    pseudo[8] = 0;
    pseudo[9] = IPPROTO_TCP;
    uint16_t tlen = htons((uint16_t)tcp_len);

    memcpy(pseudo + 10, &tlen, 2);
    memcpy(pseudo + 12, tcp, tcp_len);

    unsigned short chk = ip_checksum((unsigned short *)pseudo, psize);
    free(pseudo);

    return chk;
}

// Get Source IP Address
in_addr_t get_source_inaddr(void)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 0;

    struct sockaddr_in serv;
    memset(&serv,0,sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    if (connect(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0)
    {
        close(sock);
        return 0;
    }

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0)
    {
        close(sock);
        return 0;
    }

    close(sock);

    return name.sin_addr.s_addr;
}


int main(int argc, char *argv[])
{
    int opt;
    int max_hops = 30;
    int destination_port = 80;
    char *target = NULL;

    srand(time(NULL));

    // --help
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0)
            goto print_help;
    }

    // Command Line Arguments
    while ((opt = getopt(argc, argv, "m:p:t:h")) != -1)
    {
        switch(opt) {
            case 'm':
                max_hops = atoi(optarg);
                break;
            case 'p':
                destination_port = atoi(optarg);
                break;
            case 't':
                target = optarg;
                break;
            case 'h':
            default:
            print_help:
                printf("usage: %s [-m MAX_HOPS] [-p DST_PORT] -t TARGET\n", argv[0]);
                printf("\noptional arguments:\n");
                printf("-h, --help    show this help message and exit\n");
                printf("-m  MAX_HOPS  Max hops to probe (default = 30)\n");
                printf("-p  DST_PORT  TCP destination port (default = 80)\n");
                printf("-t  TARGET    Target domain or IP\n");
                return 0;
        }
    }

    // Target is Required
    if (!target)
    {
        fprintf(stderr,"Target is required (-t)\n");
        return 1;
    }

    // Resolve Target Hostname
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;

    if (getaddrinfo(target, NULL, &hints, &res) != 0 || res == NULL)
    {
        fprintf(stderr, "ERROR: Could not resolve target address: %s\n", target);
        return 1;
    }

    // Destination Address
    struct sockaddr_in dest_address;
    memcpy(&dest_address, res->ai_addr, sizeof(struct sockaddr_in));
    dest_address.sin_port = htons(destination_port);

    freeaddrinfo(res);

    char destination_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_address.sin_addr, destination_ip, sizeof(destination_ip));

    // Get Source IP Address
    in_addr_t source_s = inet_addr(VM_IP);
    if (source_s == INADDR_NONE)
        source_s = get_source_inaddr();

    if (source_s == 0)
    {
        fprintf(stderr,"ERROR: Could not get source IP address.\n");
        return 1;
    }

    struct in_addr source_ip = { source_s };

    // Print Starting Information
    printf("Traceroute to %s (%s), %d Hops MAX, TCP SYN to Port %d\n", target, destination_ip, max_hops, destination_port);

    // Socket Setup
    int recv_icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (recv_icmp_sock < 0)
    {
        return 1;
    }

    int recv_tcp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (recv_tcp_sock < 0)
    {
        close(recv_icmp_sock);
        return 1;
    }

    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (send_sock < 0)
    {
        close(recv_icmp_sock);
        close(recv_tcp_sock);
        return 1; }

    struct timeval timeout_tv = {1,0};
    setsockopt(recv_icmp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout_tv, sizeof(timeout_tv));
    setsockopt(recv_tcp_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout_tv, sizeof(timeout_tv));

    int one = 1;

    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        close(send_sock);
        close(recv_icmp_sock);
        close(recv_tcp_sock);
        return 1;
    }

    int maxfd;
    if (recv_icmp_sock > recv_tcp_sock)
        maxfd = recv_icmp_sock;
    else
        maxfd = recv_tcp_sock;

    // TTL Loop
    for (int ttl=1; ttl <= max_hops; ttl++)
    {
        printf("%2d  ", ttl);
        fflush(stdout);

        int reached = 0;
        int probe_matched[3] = {0};
        double probe_rtt[3] = {0.0};
        char probe_ip[3][INET_ADDRSTRLEN];
        char probe_name[3][256];

        for (int k=0;k<3;k++)
        {
            probe_ip[k][0]=0; probe_name[k][0]=0;
        }

        for (int i=0;i<3;i++)
        {
            unsigned short src_port = 49152 + (rand() % 16384);
            char packet[4096];
            memset(packet,0,sizeof(packet));
            struct iphdr *ip = (struct iphdr *)packet;
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

            // IP Header
            ip->ihl = 5;
            ip->version = 4;
            ip->tos = 0;
            ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            ip->id = htons(rand() & 0xFFFF);
            ip->frag_off = 0;
            ip->ttl = ttl;
            ip->protocol = IPPROTO_TCP;
            ip->saddr = source_ip.s_addr;
            ip->daddr = dest_address.sin_addr.s_addr;
            ip->check = 0;
            ip->check = ip_checksum((unsigned short *)ip, sizeof(struct iphdr));

            // TCP Header
            memset(tcp,0,sizeof(struct tcphdr));
            tcp->source = htons(src_port);
            tcp->dest = htons(destination_port);
            tcp->seq = htonl(rand());
            tcp->ack_seq = 0;
            tcp->doff = 5;
            tcp->syn = 1;
            tcp->window = htons(65535);
            tcp->check = 0;
            tcp->check = tcp_checksum(ip, tcp, sizeof(struct tcphdr));

            // Send Packet
            struct timeval start, recvtime;
            gettimeofday(&start, NULL);

            ssize_t sent = sendto(send_sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&dest_address, sizeof(dest_address));

            if (sent < 0)
            {
                probe_matched[i] = 0;
                continue;
            }

            // Wait for Reply
            int matched = 0;
            double rtt_ms = 0.0;
            char reply_ip[INET_ADDRSTRLEN] = {0};
            char reply_name[256] = {0};
            int probe_reached = 0;

            struct timeval deadline = start;
            deadline.tv_sec += 1;

            while (1) {
                struct timeval now;
                gettimeofday(&now, NULL);
                long rem_usec = (deadline.tv_sec - now.tv_sec) * 1000000L + (deadline.tv_usec - now.tv_usec);
                if (rem_usec <= 0)
                    break;

                struct timeval tv;
                tv.tv_sec = rem_usec / 1000000L;
                tv.tv_usec = rem_usec % 1000000L;

                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(recv_icmp_sock, &readfds);
                FD_SET(recv_tcp_sock, &readfds);

                int sel = select(maxfd + 1, &readfds, NULL, NULL, &tv);
                if (sel < 0)
                {
                    if (errno==EINTR)
                    continue;

                    break;
                }
                else if (sel == 0)
                    continue;

                // ICMP Reply
                if (FD_ISSET(recv_icmp_sock, &readfds))
                {
                    char buf[4096];
                    struct sockaddr_in raddr;
                    socklen_t alen = sizeof(raddr);
                    int n = recvfrom(recv_icmp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&raddr, &alen);
                    if (n <= 0)
                        continue;

                    gettimeofday(&recvtime, NULL);
                    struct iphdr *rip = (struct iphdr *)buf;
                    int rip_len = rip->ihl * 4;
                    
                    if (n < rip_len + (int)sizeof(struct icmphdr))
                        continue;

                    struct icmphdr *icmp = (struct icmphdr *)(buf + rip_len);
                    int icmp_payload_offset = rip_len + sizeof(struct icmphdr);

                    if (n < icmp_payload_offset + (int)sizeof(struct iphdr) + 8)
                        continue;

                    struct iphdr *orig_ip = (struct iphdr *)(buf + icmp_payload_offset);
                    struct tcphdr *orig_tcp = (struct tcphdr *)((char *)orig_ip + (orig_ip->ihl * 4));

                    if (orig_tcp->source == htons(src_port) && orig_tcp->dest == htons(destination_port))
                    {
                        matched = 1;
                        rtt_ms = (recvtime.tv_sec - start.tv_sec) * 1000.0 + (recvtime.tv_usec - start.tv_usec) / 1000.0;
                        inet_ntop(AF_INET, &raddr.sin_addr, reply_ip, sizeof(reply_ip));
                        
                        strncpy(reply_name, reply_ip, sizeof(reply_name)-1);
                        struct hostent *h = gethostbyaddr((const char *)&raddr.sin_addr, sizeof(raddr.sin_addr), AF_INET);
                        if (h)
                            strncpy(reply_name, h->h_name, sizeof(reply_name)-1);

                        if (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_PORT_UNREACH)
                        {
                            probe_reached = 1;
                        }
                        else if (icmp->type == ICMP_TIME_EXCEEDED && icmp->code == ICMP_EXC_TTL)
                        {
                            probe_reached = 0;
                        }
                        else
                        {
                            matched = 0;
                        }

                        if (matched) break;
                    }
                }

                // TCP Reply
                if (FD_ISSET(recv_tcp_sock, &readfds))
                {
                    char buf[4096];
                    struct sockaddr_in raddr;
                    socklen_t alen = sizeof(raddr);
                    int n = recvfrom(recv_tcp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&raddr, &alen);
                    if (n <= 0)
                        continue;

                    gettimeofday(&recvtime, NULL);
                    
                    struct iphdr *rip = (struct iphdr *)buf;
                    int rip_len = rip->ihl * 4;
                    if (n < rip_len + (int)sizeof(struct tcphdr))
                        continue;

                    struct tcphdr *rtcp = (struct tcphdr *)(buf + rip_len);

                    if (rtcp->dest == htons(src_port) && rtcp->source == htons(destination_port))
                    {
                        matched = 1;
                        rtt_ms = (recvtime.tv_sec - start.tv_sec) * 1000.0 + (recvtime.tv_usec - start.tv_usec) / 1000.0;
                        inet_ntop(AF_INET, &raddr.sin_addr, reply_ip, sizeof(reply_ip));
                        
                        strncpy(reply_name, reply_ip, sizeof(reply_name)-1);
                        struct hostent *h = gethostbyaddr((const char *)&raddr.sin_addr, sizeof(raddr.sin_addr), AF_INET);
                        if (h) 
                            strncpy(reply_name, h->h_name, sizeof(reply_name)-1);

                        if ((rtcp->syn && rtcp->ack) || rtcp->rst)
                        {
                            probe_reached = 1;
                        }
                        else
                        {
                            matched = 0;
                        }
                        if (matched)
                            break;
                    }
                }
            }

            if (matched) {
                probe_matched[i] = 1;
                probe_rtt[i] = rtt_ms;
                strncpy(probe_ip[i], reply_ip, sizeof(probe_ip[i]) - 1);
                strncpy(probe_name[i], reply_name, sizeof(probe_name[i]) - 1);
                if (probe_reached)
                    reached = 1;
            }
            else
            {
                probe_matched[i] = 0;
            }
            if (reached && i < 2)
            {
                break;
            }
        }

        // Print Results
        int matched_any = (probe_matched[0] || probe_matched[1] || probe_matched[2]);

        if (!matched_any)
        {
            printf(" * * *\n");
        }
        else
        {
            int same = 1;
            char *firstip = NULL;
            for (int j=0;j<3;j++)
            {
                if (probe_matched[j])
                {
                    firstip = probe_ip[j];
                    break;
                }
            }

            for (int j=0;j<3;j++)
            {
                if (probe_matched[j] && strcmp(probe_ip[j], firstip) != 0)
                    same = 0;
            }

            if (same && firstip)
            {
                char *name = NULL;
                
                for (int j=0;j<3;j++)
                {
                    if (probe_matched[j])
                    {
                        name = probe_name[j];
                        break;
                    }
                }
                
                if (name && strlen(name)) {
                    printf(" %s (%s)", name, firstip);
                }
                else
                {
                    printf(" %s (%s)", firstip, firstip);
                }

                for (int j=0;j<3;j++) {
                    if (probe_matched[j])
                        printf("  %.3f ms", probe_rtt[j]);
                    
                    else
                        printf("  *");
                }

                printf("\n");

            }
            else
            {
                for (int j=0;j<3;j++)
                {
                    if (probe_matched[j])
                    {
                        printf(" %s (%s)  %.3f ms", (strlen(probe_name[j])?probe_name[j]:probe_ip[j]), probe_ip[j], probe_rtt[j]);
                    }
                    else
                    {
                        printf(" *");
                    }
                }

                printf("\n");
            }
        }

        if (reached) break;
    }

    close(send_sock);
    close(recv_icmp_sock);
    close(recv_tcp_sock);
    return 0;
}