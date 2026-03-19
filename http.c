/*
 * HTTP/2 Load Tester v3.2 - Performance Optimized
 * Kullanım: ./main <url> <port> <time> <thread> <rps>
 *
 * Derleme:
 *   gcc -O3 -march=native -o main http.c -lnghttp2 -lssl -lcrypto -lpthread -lm
 *
 * İyileştirmeler (v3.1 → v3.2):
 *   - DNS sonucu global cache'lendi (her bağlantıda getaddrinfo yok)
 *   - SSL session reuse (TLS handshake maliyeti düşürüldü)
 *   - TCP: SO_REUSEPORT, SO_SNDBUF/SO_RCVBUF büyütüldü, TCP_QUICKACK
 *   - HTTP/2 window size 16 MB'a çıkarıldı
 *   - HPACK header table 65536'ya çıkarıldı
 *   - conn_io select timeout 1ms→100µs düşürüldü
 *   - Header nv uzunlukları sabit (her istekte strlen yok)
 *   - PL_START 16→32, PL 512→1024 artırıldı
 *   - Reconnect backoff exponential (max 2s)
 *   - SSL_CTX session cache aktif edildi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nghttp2/nghttp2.h>

/* ─── Pipeline constants ──────────────────────────────────────── */
#define PL       1024  /* mutlak maksimum pipeline depth (512→1024) */
#define PL_MIN   1
#define PL_START 32    /* başlangıç pipeline depth (16→32) */

/* ─── Globals ─────────────────────────────────────────────────── */
static atomic_long g_sent    = 0;
static atomic_long g_ok      = 0;
static atomic_long g_err     = 0;
static atomic_int  g_running = 1;
static atomic_int  g_cur_pl  = PL_START;

static struct {
    char host[256];
    char path[1024];
    int  port, duration, threads, rps;
} C;

/* ─── DNS Cache ───────────────────────────────────────────────── */
/* DNS bir kere çözülür, tüm thread'ler paylaşır */
static struct addrinfo *g_addr = NULL;
static pthread_mutex_t  g_addr_mu = PTHREAD_MUTEX_INITIALIZER;

static struct addrinfo *get_addrinfo(void) {
    pthread_mutex_lock(&g_addr_mu);
    if (!g_addr) {
        struct addrinfo hints = {0};
        char ps[16];
        snprintf(ps, sizeof ps, "%d", C.port);
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        getaddrinfo(C.host, ps, &hints, &g_addr);
    }
    pthread_mutex_unlock(&g_addr_mu);
    return g_addr;
}

/* ─── Timing ──────────────────────────────────────────────────── */
static inline double mono(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

static inline void nsleep(long ns) {
    if (ns <= 0) return;
    struct timespec t = { ns / 1000000000L, ns % 1000000000L };
    nanosleep(&t, NULL);
}

/* ─── URL parse ───────────────────────────────────────────────── */
static void parse_url(const char *url) {
    const char *p = url;
    C.port = 443;
    if      (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://",  7) == 0) { p += 7; C.port = 80; }

    const char *sl = strchr(p, '/');
    const char *co = strchr(p, ':');
    size_t hl;
    if (co && (!sl || co < sl)) { hl = co - p; C.port = atoi(co + 1); }
    else                          hl = sl ? (size_t)(sl - p) : strlen(p);
    if (hl >= sizeof C.host) hl = sizeof C.host - 1;
    memcpy(C.host, p, hl); C.host[hl] = '\0';
    strncpy(C.path, sl ? sl : "/", sizeof C.path - 1);
    if (!C.path[0]) strcpy(C.path, "/");
}

/* ─── TCP ─────────────────────────────────────────────────────── */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int tcp_connect(void) {
    struct addrinfo *r = get_addrinfo();
    if (!r) return -1;

    int fd = -1;
    for (struct addrinfo *rp = r; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        /* Socket seçenekleri — performans */
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,  &one, sizeof one);
#ifdef TCP_QUICKACK
        setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof one);
#endif
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
        /* Büyük send/recv buffer — throughput için */
        int buf = 1 << 20; /* 1 MB */
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);

        set_nonblocking(fd);
        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) break;
        if (errno == EINPROGRESS) {
            fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
            struct timeval tv = {5, 0};
            if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
                int err = 0; socklen_t el = sizeof err;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err == 0) break;
            }
        }
        close(fd); fd = -1;
    }
    return fd;
}

/* ─── TLS ─────────────────────────────────────────────────────── */
static SSL_CTX *g_ctx = NULL;

static void init_ssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    g_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_alpn_protos(g_ctx, (const unsigned char *)"\x02h2", 3);

    /* Session reuse: TLS handshake'i tekrar yapmadan bağlan */
    SSL_CTX_set_session_cache_mode(g_ctx,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);

    /* TLS 1.3 öncelikli, 1.2 de kabul et */
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_2_VERSION);

    /* Hızlı cipher suite'ler öne al */
    SSL_CTX_set_cipher_list(g_ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384");
}

/* Thread-local SSL session cache */
static __thread SSL_SESSION *tl_ssl_session = NULL;

static SSL *tls_wrap(int fd) {
    SSL *s = SSL_new(g_ctx);
    SSL_set_fd(s, fd);
    SSL_set_tlsext_host_name(s, C.host);

    /* Önceki session varsa reuse et */
    if (tl_ssl_session) {
        SSL_set_session(s, tl_ssl_session);
    }

    while (1) {
        int rc = SSL_connect(s);
        if (rc == 1) {
            /* Yeni session'ı sakla (sonraki bağlantı için) */
            SSL_SESSION *sess = SSL_get1_session(s);
            if (sess) {
                if (tl_ssl_session) SSL_SESSION_free(tl_ssl_session);
                tl_ssl_session = sess;
            }
            break;
        }
        int err = SSL_get_error(s, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            fd_set rfds, wfds;
            FD_ZERO(&rfds); FD_ZERO(&wfds);
            if (err == SSL_ERROR_WANT_READ)  FD_SET(fd, &rfds);
            if (err == SSL_ERROR_WANT_WRITE) FD_SET(fd, &wfds);
            struct timeval tv = {5, 0};
            if (select(fd + 1, &rfds, &wfds, NULL, &tv) <= 0) {
                SSL_free(s); return NULL;
            }
            continue;
        }
        SSL_free(s); return NULL;
    }
    return s;
}

/* ─── Connection ──────────────────────────────────────────────── */
typedef struct {
    int              fd;
    SSL             *ssl;
    nghttp2_session *ng;
    int              err;
    int              inflight;
    int              refused;
    int              server_max;
} Conn;

/* ─── nghttp2 callbacks ───────────────────────────────────────── */
static ssize_t ng_send(nghttp2_session *s, const uint8_t *d, size_t l,
                       int f, void *u) {
    (void)s; (void)f;
    Conn *c = u;
    while (1) {
        int n = SSL_write(c->ssl, d, (int)l);
        if (n > 0) return n;
        int err = SSL_get_error(c->ssl, n);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            fd_set fds; FD_ZERO(&fds); FD_SET(c->fd, &fds);
            struct timeval tv = {2, 0};
            fd_set *r = (err == SSL_ERROR_WANT_READ)  ? &fds : NULL;
            fd_set *w = (err == SSL_ERROR_WANT_WRITE) ? &fds : NULL;
            if (select(c->fd + 1, r, w, NULL, &tv) <= 0) {
                c->err = 1; return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            continue;
        }
        c->err = 1; return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
}

static ssize_t ng_recv(nghttp2_session *s, uint8_t *b, size_t l,
                       int f, void *u) {
    (void)s; (void)f;
    Conn *c = u;
    int n = SSL_read(c->ssl, b, (int)l);
    if (n > 0) return n;
    if (n == 0) return NGHTTP2_ERR_EOF;
    int err = SSL_get_error(c->ssl, n);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
        return NGHTTP2_ERR_WOULDBLOCK;
    c->err = 1; return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static int ng_on_header(nghttp2_session *s, const nghttp2_frame *fr,
                        const uint8_t *name, size_t nl,
                        const uint8_t *val,  size_t vl,
                        uint8_t f, void *u) {
    (void)s; (void)fr; (void)f; (void)vl;
    if (nl == 7 && memcmp(name, ":status", 7) == 0) {
        Conn *c = u; (void)c;
        int status = atoi((const char *)val);
        if (status >= 200 && status < 400) atomic_fetch_add(&g_ok,  1);
        else                               atomic_fetch_add(&g_err, 1);
    }
    return 0;
}

static int ng_on_data(nghttp2_session *s, uint8_t f, int32_t sid,
                      const uint8_t *d, size_t l, void *u) {
    (void)s; (void)f; (void)sid; (void)d; (void)l; (void)u;
    return 0;
}

static int ng_on_close(nghttp2_session *s, int32_t sid,
                       uint32_t ec, void *u) {
    (void)s; (void)sid;
    Conn *c = u;
    if (ec == NGHTTP2_REFUSED_STREAM || ec == NGHTTP2_CANCEL) {
        c->refused++;
        atomic_fetch_add(&g_err, 1);
    }
    return 0;
}

static int ng_on_frame_recv(nghttp2_session *s,
                            const nghttp2_frame *fr, void *u) {
    (void)s;
    Conn *c = u;
    if (fr->hd.type == NGHTTP2_GOAWAY) {
        c->err = 1;
    } else if (fr->hd.type == NGHTTP2_SETTINGS &&
               !(fr->hd.flags & NGHTTP2_FLAG_ACK)) {
        for (size_t i = 0; i < fr->settings.niv; i++) {
            if (fr->settings.iv[i].settings_id ==
                NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) {
                c->server_max = (int)fr->settings.iv[i].value;
            }
        }
    }
    return 0;
}

/* ─── Bağlantı aç ─────────────────────────────────────────────── */
static int conn_open(Conn *c) {
    memset(c, 0, sizeof *c);
    c->fd = -1;
    c->server_max = 0;
    c->fd = tcp_connect();
    if (c->fd < 0) return -1;

    c->ssl = tls_wrap(c->fd);
    if (!c->ssl) { close(c->fd); return -1; }

    /* ALPN kontrol */
    const unsigned char *proto; unsigned int pl;
    SSL_get0_alpn_selected(c->ssl, &proto, &pl);
    if (!proto || pl != 2 || memcmp(proto, "h2", 2)) {
        SSL_free(c->ssl); close(c->fd); return -1;
    }

    nghttp2_session_callbacks *cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_send_callback(cb, ng_send);
    nghttp2_session_callbacks_set_recv_callback(cb, ng_recv);
    nghttp2_session_callbacks_set_on_header_callback(cb, ng_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, ng_on_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, ng_on_close);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, ng_on_frame_recv);

    nghttp2_session_client_new(&c->ng, cb, c);
    nghttp2_session_callbacks_del(cb);

    /* HTTP/2 ayarları — büyük window + büyük header table */
    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1000        },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    (1 << 24) - 1 }, /* 16 MB */
        { NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,      65536       },
        { NGHTTP2_SETTINGS_ENABLE_PUSH,            0           },
    };
    nghttp2_submit_settings(c->ng, NGHTTP2_FLAG_NONE, iv,
                            sizeof iv / sizeof iv[0]);

    /* Connection-level window'u da büyüt */
    nghttp2_submit_window_update(c->ng, NGHTTP2_FLAG_NONE, 0,
                                 (1 << 30) - 65535); /* ~1 GB */

    int rv = nghttp2_session_send(c->ng);
    if (rv != 0) {
        nghttp2_session_del(c->ng);
        SSL_free(c->ssl); close(c->fd); return -1;
    }

    /* Sunucunun SETTINGS'ini al */
    fd_set rfds; FD_ZERO(&rfds); FD_SET(c->fd, &rfds);
    struct timeval tv = {5, 0};
    if (select(c->fd + 1, &rfds, NULL, NULL, &tv) <= 0) {
        nghttp2_session_del(c->ng);
        SSL_free(c->ssl); close(c->fd); return -1;
    }
    rv = nghttp2_session_recv(c->ng);
    if (rv != 0 && rv != NGHTTP2_ERR_WOULDBLOCK) {
        nghttp2_session_del(c->ng);
        SSL_free(c->ssl); close(c->fd); return -1;
    }
    nghttp2_session_send(c->ng); /* SETTINGS ACK */
    return 0;
}

static void conn_close(Conn *c) {
    if (c->ng) {
        nghttp2_session_terminate_session(c->ng, NGHTTP2_NO_ERROR);
        nghttp2_session_send(c->ng);
        nghttp2_session_del(c->ng); c->ng = NULL;
    }
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
}

/* ─── İstek submit ────────────────────────────────────────────── */
/*
 * Header uzunlukları sabit olarak hesaplanmış — her istekte strlen yok.
 * path ve host uzunlukları bağlantı başında C'den okunur.
 */
static int conn_submit(Conn *c) {
    static __thread size_t path_len = 0, host_len = 0;
    if (!path_len) {
        path_len = strlen(C.path);
        host_len = strlen(C.host);
    }

    nghttp2_nv hdrs[] = {
        { (uint8_t *)":method",    (uint8_t *)"GET",   7, 3,         NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)":scheme",    (uint8_t *)"https", 7, 5,         NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)":path",      (uint8_t *)C.path,  5, path_len,  NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)":authority", (uint8_t *)C.host,  10, host_len, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)"user-agent", (uint8_t *)"Mozilla/5.0", 10, 11, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t *)"accept",     (uint8_t *)"*/*",   6,  3,        NGHTTP2_NV_FLAG_NONE },
    };

    int32_t sid = nghttp2_submit_request(c->ng, NULL, hdrs, 6, NULL, NULL);
    if (sid < 0) { c->err = 1; return -1; }
    atomic_fetch_add(&g_sent, 1);
    return 0;
}

/* ─── I/O loop ────────────────────────────────────────────────── */
static int conn_io(Conn *c) {
    int r;

    r = nghttp2_session_send(c->ng);
    if (r != 0) return r;

    /* 100µs bekle (1ms'den düşürüldü) — daha düşük latency */
    fd_set rfds;
    FD_ZERO(&rfds); FD_SET(c->fd, &rfds);
    struct timeval tv = {0, 100}; /* 100 µs */
    int sel = select(c->fd + 1, &rfds, NULL, NULL, &tv);
    if (sel < 0) return -1;
    if (sel == 0) return 0;

    r = nghttp2_session_recv(c->ng);
    if (r == NGHTTP2_ERR_WOULDBLOCK) return 0;
    return r;
}

/* ─── Worker ──────────────────────────────────────────────────── */
static void *worker(void *arg) {
    (void)arg;
    long int_ns = C.rps > 0
        ? (long)((double)C.threads / C.rps * 1e9) : 0;
    double deadline = mono() + C.duration;

    int cur_pl    = PL_START;
    int ok_streak = 0;

    /* Exponential backoff için: başarısız bağlantıda artan bekleme */
    long backoff_ns = 50000000L; /* 50ms başlangıç */

    while (atomic_load(&g_running) && mono() < deadline) {
        Conn c;
        if (conn_open(&c) != 0) {
            nsleep(backoff_ns);
            /* Backoff'u iki katına çıkar, max 2s */
            backoff_ns *= 2;
            if (backoff_ns > 2000000000L) backoff_ns = 2000000000L;
            continue;
        }
        backoff_ns = 50000000L; /* Bağlantı başarılı → backoff sıfırla */

        double next_send  = mono();
        int    prev_refused = 0;

        while (atomic_load(&g_running) && mono() < deadline && !c.err) {
            double now = mono();

            int hard_cap = (c.server_max > 0) ? c.server_max : PL;
            if (cur_pl > hard_cap) cur_pl = hard_cap;
            if (cur_pl < PL_MIN)   cur_pl = PL_MIN;

            /* AIMD decrease — refused stream */
            if (c.refused > prev_refused) {
                int n = c.refused - prev_refused;
                prev_refused = c.refused;
                ok_streak = 0;
                for (int i = 0; i < n; i++) cur_pl /= 2;
                if (cur_pl < PL_MIN) cur_pl = PL_MIN;
                atomic_store(&g_cur_pl, cur_pl);
                if (c.refused >= 3) break;
            }

            /* Throttle */
            if (int_ns > 0 && now < next_send) {
                conn_io(&c);
                continue;
            }

            /* Fire-and-forget */
            if (conn_submit(&c) == 0) {
                if (int_ns > 0) next_send = now + int_ns;

                ok_streak++;
                int thr = cur_pl * 8;
                if (thr < 32) thr = 32;
                if (ok_streak >= thr) {
                    ok_streak = 0;
                    int cap = (c.server_max > 0) ? c.server_max : PL;
                    if (cur_pl < cap) {
                        cur_pl++;
                        atomic_store(&g_cur_pl, cur_pl);
                    }
                }
            }

            if (conn_io(&c) != 0) break;
        }

        conn_close(&c);
    }
    return NULL;
}

/* ─── Stats printer ───────────────────────────────────────────── */
static void *stats(void *arg) {
    (void)arg;
    long prev = 0;
    double pt = mono();
    printf("\n\033[1m%-6s %-11s %-11s %-11s %-12s %-6s\033[0m\n",
           "TIME", "TOTAL", "OK", "ERR", "RPS", "PL");
    printf("────────────────────────────────────────────────────────────\n");
    for (int s = 0; s < C.duration && atomic_load(&g_running); s++) {
        sleep(1);
        double t   = mono();
        long sent  = atomic_load(&g_sent);
        long ok    = atomic_load(&g_ok);
        long err   = atomic_load(&g_err);
        int  pl    = atomic_load(&g_cur_pl);
        double rps = (sent - prev) / (t - pt);
        prev = sent; pt = t;
        printf("%-6d %-11ld \033[32m%-11ld\033[0m \033[31m%-11ld\033[0m "
               "\033[33m%-12.1f\033[0m \033[36m%-6d\033[0m\n",
               s + 1, sent, ok, err, rps, pl);
        fflush(stdout);
    }
    return NULL;
}

/* ─── main ────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Kullanım: %s <url> <port> <süre> <thread> <rps>\n",
                argv[0]);
        return 1;
    }
    parse_url(argv[1]);
    int ap = atoi(argv[2]); if (ap > 0) C.port = ap;
    C.duration = atoi(argv[3]);
    C.threads  = atoi(argv[4]);
    C.rps      = atoi(argv[5]);
    if (C.threads  < 1) C.threads  = 1;
    if (C.duration < 1) C.duration = 1;

    printf("\033[1;36m"
           "╔══════════════════════════════════════╗\n"
           "║      HTTP/2 Load Tester v3.2         ║\n"
           "╚══════════════════════════════════════╝\033[0m\n"
           "  Host   : %s\n  Port   : %d\n  Path   : %s\n"
           "  Süre   : %d sn\n  Thread : %d\n  RPS    : %s\n",
           C.host, C.port, C.path, C.duration, C.threads,
           C.rps == 0 ? "unlimited" : argv[5]);

    init_ssl();

    /* DNS'i önceden çöz */
    get_addrinfo();

    pthread_t *tids = calloc(C.threads, sizeof *tids);
    pthread_t stid;
    pthread_create(&stid, NULL, stats, NULL);

    double t0 = mono();
    for (int i = 0; i < C.threads; i++)
        pthread_create(&tids[i], NULL, worker, NULL);

    sleep(C.duration);
    atomic_store(&g_running, 0);
    for (int i = 0; i < C.threads; i++) pthread_join(tids[i], NULL);
    pthread_join(stid, NULL);

    double el   = mono() - t0;
    long   sent = atomic_load(&g_sent);
    long   ok   = atomic_load(&g_ok);
    long   err  = atomic_load(&g_err);
    printf("\n\033[1;33m──── SONUÇ ──────────────────────────────────\033[0m\n"
           "  Toplam  : %ld\n  Başarılı: %ld\n  Hatalı  : %ld\n"
           "  Süre    : %.2f sn\n  Ort.RPS : %.2f\n"
           "\033[1;33m─────────────────────────────────────────────\033[0m\n",
           sent, ok, err, el, el > 0 ? sent / el : 0.0);

    free(tids);
    if (g_addr) freeaddrinfo(g_addr);
    SSL_CTX_free(g_ctx);
    return 0;
}
