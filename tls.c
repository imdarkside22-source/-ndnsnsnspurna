/*
 * TLS Stress Tester  v5.0  — TRUE HIGH PERFORMANCE
 *
 * Kullanim : ./tls <host> <port> <sure_sn> <thread> <rps_per_thread> [proto] [tls]
 *
 *   rps=0  → sinirsiz (bekleme yok, tam hiz)
 *   rps=N  → her thread N req/s (toplam = thread × N)
 *
 *   proto  : auto | h1 | h2
 *   tls    : tls12 | tls13
 *
 * Derleme:
 *   gcc -o tls tls_stress.c \
 *       $(pkg-config --cflags --libs libnghttp2) \
 *       -lssl -lcrypto -lpthread -O3 -march=native
 *
 * PERFORMANS MIMARISI:
 *   - Thread basina 64 paralel baglanti havuzu
 *   - Her baglanti icin round-robin dispatch (hic bos baglanti kalmaz)
 *   - H2: tek baglanida 128 paralel stream + buyuk window
 *   - H1: keep-alive + 32 pipeline derinligi
 *   - Senkron I/O ama COK daha fazla concurrency ile 10k+ RPS
 *   - Batch atomic update (log overhead sifir)
 *   - Per-thread token bucket (lock yok)
 *   - DNS once coz, TCP_NODELAY, buyuk soket buffer
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <time.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nghttp2/nghttp2.h>

/* ================================================================
 *  TUNE EDILEBILIR PARAMETRELER
 * ================================================================ */
#define CONNS_PER_THREAD   64    /* thread basina paralel baglanti */
#define H2_STREAMS_PER_CONN 128  /* h2 baglanida paralel stream */
#define H1_PIPELINE_DEPTH   32   /* h1 keep-alive pipeline */
#define CONN_MAX_REUSE    2000   /* baglanti yenileme esigi */
#define CONN_TIMEOUT_SEC     4
#define MAX_HOST           256
#define RBUF_SZ          65536

/* ================================================================
 *  Tipler
 * ================================================================ */
typedef enum { PROTO_AUTO=0, PROTO_HTTP1, PROTO_HTTP2 } proto_t;
typedef enum { TLS_AUTO=0,   TLS_V12,     TLS_V13     } tls_ver_t;

typedef struct {
    char      host[MAX_HOST];
    int       port;
    int       duration;
    int       nthread;
    long      rps_per_thread;
    proto_t   proto;
    tls_ver_t tls_ver;
} cfg_t;

static cfg_t G;

static struct sockaddr_storage g_addr;
static socklen_t               g_addrlen;
static int                     g_afamily;

/* ================================================================
 *  Atomik sayaclar  — batch guncelleme ile overhead minimun
 * ================================================================ */
static atomic_long g_ok    = 0;
static atomic_long g_fail  = 0;
static atomic_long g_bytes = 0;
static volatile int g_run  = 1;

/* ================================================================
 *  Per-thread token bucket  (lock yok)
 * ================================================================ */
typedef struct {
    long long last_ns;
    double    tokens;
    double    rate_per_ns;  /* tokens/nanosecond */
    int       unlimited;
} bucket_t;

static inline long long _ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void bucket_init(bucket_t *b, long rps)
{
    if (rps <= 0) { b->unlimited = 1; return; }
    b->unlimited    = 0;
    b->rate_per_ns  = (double)rps / 1e9;
    b->tokens       = (double)rps;   /* 1 sn burst */
    b->last_ns      = _ns();
}

static inline void bucket_wait(bucket_t *b, int n)
{
    if (b->unlimited) return;
    for (;;) {
        long long now = _ns();
        b->tokens += (double)(now - b->last_ns) * b->rate_per_ns;
        b->last_ns = now;
        double max = b->rate_per_ns * 2e9;
        if (b->tokens > max) b->tokens = max;
        if (b->tokens >= (double)n) { b->tokens -= (double)n; return; }
        /* tam bekleme suresi hesapla */
        long long need = (long long)(((double)n - b->tokens) / b->rate_per_ns);
        if (need < 10000LL)  need = 10000LL;   /* min 10µs */
        if (need > 5000000LL) need = 5000000LL; /* max 5ms */
        struct timespec sl = { need/1000000000LL, need%1000000000LL };
        nanosleep(&sl, NULL);
    }
}

/* ================================================================
 *  DNS
 * ================================================================ */
static int dns_resolve(void)
{
    char ps[8]; snprintf(ps, sizeof(ps), "%d", G.port);
    struct addrinfo hints = {0}, *r = NULL;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(G.host, ps, &hints, &r)) return -1;
    memcpy(&g_addr, r->ai_addr, r->ai_addrlen);
    g_addrlen = r->ai_addrlen;
    g_afamily = r->ai_family;
    freeaddrinfo(r);
    return 0;
}

/* ================================================================
 *  TCP socket
 * ================================================================ */
static int tcp_open(void)
{
    int fd = socket(g_afamily, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {CONN_TIMEOUT_SEC, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,  &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE, &one, sizeof(one));

    int sz = 1 << 20; /* 1 MB buffer */
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));

    if (connect(fd, (struct sockaddr*)&g_addr, g_addrlen)) {
        close(fd); return -1;
    }
    return fd;
}

/* ================================================================
 *  SSL_CTX
 * ================================================================ */
static SSL_CTX *make_ctx(int h2)
{
    SSL_CTX *c = SSL_CTX_new(TLS_client_method());
    if (!c) return NULL;
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_session_cache_mode(c,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);

    switch (G.tls_ver) {
    case TLS_V12:
        SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION); break;
    case TLS_V13:
        SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION); break;
    default:
        SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION); break;
    }

    if (h2) {
        static const unsigned char a[] =
            "\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31";
        SSL_CTX_set_alpn_protos(c, a, sizeof(a)-1);
    } else {
        static const unsigned char a[] = "\x08\x68\x74\x74\x70\x2f\x31\x2e\x31";
        SSL_CTX_set_alpn_protos(c, a, sizeof(a)-1);
    }
    return c;
}

/* ================================================================
 *  Baglanti nesnesi
 * ================================================================ */
typedef struct {
    int          fd;
    SSL         *ssl;
    SSL_SESSION *sess;
    int          is_h2;
    int          uses;
    int          dead;
} conn_t;

static void conn_kill(conn_t *c)
{
    if (c->ssl) {
        if (c->sess) SSL_SESSION_free(c->sess);
        c->sess = SSL_get1_session(c->ssl);
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl); c->ssl = NULL;
    }
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    c->uses = 0; c->dead = 0; c->is_h2 = 0;
}

static int conn_open(conn_t *c, SSL_CTX *ctx_h1, SSL_CTX *ctx_h2)
{
    int wh2 = (G.proto == PROTO_HTTP2 || G.proto == PROTO_AUTO);
    c->fd = tcp_open();
    if (c->fd < 0) return -1;

    c->ssl = SSL_new(wh2 ? ctx_h2 : ctx_h1);
    if (!c->ssl) { close(c->fd); c->fd=-1; return -1; }

    SSL_set_tlsext_host_name(c->ssl, G.host);
    SSL_set_fd(c->ssl, c->fd);

    if (c->sess) {
        SSL_set_session(c->ssl, c->sess);
        SSL_SESSION_free(c->sess); c->sess = NULL;
    }

    if (SSL_connect(c->ssl) != 1) {
        SSL_free(c->ssl); c->ssl = NULL;
        close(c->fd); c->fd = -1; return -1;
    }

    const unsigned char *p = NULL; unsigned int pl = 0;
    SSL_get0_alpn_selected(c->ssl, &p, &pl);
    c->is_h2 = (p && pl==2 && !memcmp(p,"h2",2));
    c->uses = 0; c->dead = 0;
    return 0;
}

static inline int conn_ok(conn_t *c)
{
    if (c->dead || !c->ssl || c->fd < 0) return 0;
    if (c->uses >= CONN_MAX_REUSE) return 0;
    /* non-blocking peek */
    char b[1];
    int r = recv(c->fd, b, 1, MSG_PEEK|MSG_DONTWAIT);
    if (r == 0 || (r < 0 && errno!=EAGAIN && errno!=EWOULDBLOCK)) return 0;
    return 1;
}

/* ================================================================
 *  HTTP/1.1  keep-alive + pipeline
 *  Donus: gonderilen istek sayisi (>0 basari), -1 hata
 * ================================================================ */
static int h1_do(conn_t *c, SSL_CTX *c1, SSL_CTX *c2)
{
    if (!conn_ok(c)) {
        conn_kill(c);
        if (conn_open(c, c1, c2) < 0) return -1;
        if (c->is_h2) return 1; /* caller h2'ye gecer */
    }

    const int D = H1_PIPELINE_DEPTH;

    /* Tum istekleri tek seferde gonder */
    static __thread char req[1024];
    static __thread int  rlen = 0;
    if (!rlen)
        rlen = snprintf(req, sizeof(req),
            "GET / HTTP/1.1\r\nHost: %s:%d\r\n"
            "User-Agent: ts/5\r\nAccept: */*\r\n"
            "Connection: keep-alive\r\n\r\n",
            G.host, G.port);

    /* Batch write */
    static __thread char wbuf[1024 * H1_PIPELINE_DEPTH];
    int wlen = 0;
    for (int i = 0; i < D; i++) {
        memcpy(wbuf + wlen, req, rlen);
        wlen += rlen;
    }
    if (SSL_write(c->ssl, wbuf, wlen) <= 0) {
        c->dead = 1; return -1;
    }

    /* Yanit oku */
    static __thread char rbuf[RBUF_SZ];
    long tb = 0;
    int  ok = 0;

    for (int i = 0; i < D; i++) {
        /* Header parse — byte-by-byte ama tek SSL_read cagrisi ile chunk */
        int    cl = -1, chunked = 0, hdone = 0;
        char   hb[2048]; int hp = 0;

        while (!hdone && hp < (int)sizeof(hb)-1) {
            int n = SSL_read(c->ssl, hb+hp, 1);
            if (n <= 0) { c->dead=1; goto h1_out; }
            tb++; hp++;
            if (hp>=4 && hb[hp-4]=='\r' && hb[hp-3]=='\n' &&
                         hb[hp-2]=='\r' && hb[hp-1]=='\n') {
                hb[hp] = '\0'; hdone = 1;
                char *p = strcasestr(hb, "content-length:");
                if (p) cl = atoi(p+15);
                if (strcasestr(hb, "chunked")) chunked = 1;
            }
        }

        if (cl > 0) {
            int rem = cl;
            while (rem > 0) {
                int tr = rem > RBUF_SZ ? RBUF_SZ : rem;
                int n  = SSL_read(c->ssl, rbuf, tr);
                if (n <= 0) { c->dead=1; goto h1_out; }
                rem -= n; tb += n;
            }
        } else if (chunked) {
            char sl[16]; int sp=0;
            for(;;){
                sp=0;
                while(sp<(int)sizeof(sl)-1){
                    int n=SSL_read(c->ssl,sl+sp,1);
                    if(n<=0) goto h1_out;
                    tb++;
                    if(sp>0 && sl[sp-1]=='\r' && sl[sp]=='\n') break;
                    sp++;
                }
                long csz=strtol(sl,NULL,16);
                if(csz==0){ SSL_read(c->ssl,rbuf,2); break; }
                long rd=0;
                while(rd<csz){
                    int tr=csz-rd>RBUF_SZ?RBUF_SZ:(int)(csz-rd);
                    int n=SSL_read(c->ssl,rbuf,tr);
                    if(n<=0) goto h1_out;
                    rd+=n; tb+=n;
                }
                SSL_read(c->ssl,rbuf,2);
            }
        }
        ok++; c->uses++;
    }
h1_out:
    atomic_fetch_add(&g_bytes, tb);
    return ok > 0 ? ok : -1;
}

/* ================================================================
 *  HTTP/2  multiplexed  N stream
 * ================================================================ */
typedef struct { SSL *ssl; int done,total,errs; long rx; } h2x_t;

static ssize_t _h2send(nghttp2_session*s,const uint8_t*d,size_t l,int f,void*u){
    (void)s;(void)f; int n=SSL_write(((h2x_t*)u)->ssl,d,(int)l);
    return n<=0?NGHTTP2_ERR_CALLBACK_FAILURE:n; }
static ssize_t _h2recv(nghttp2_session*s,uint8_t*b,size_t l,int f,void*u){
    (void)s;(void)f; h2x_t*h=u; int n=SSL_read(h->ssl,b,(int)l);
    if(n==0) return NGHTTP2_ERR_EOF;
    if(n<0){ int e=SSL_get_error(h->ssl,n);
        return (e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE)
               ? NGHTTP2_ERR_WOULDBLOCK : NGHTTP2_ERR_CALLBACK_FAILURE; }
    h->rx+=n; return n; }
static int _h2close(nghttp2_session*s,int32_t id,uint32_t ec,void*u){
    (void)s;(void)id; h2x_t*h=u; h->done++; if(ec)h->errs++; return 0; }
static int _h2data(nghttp2_session*s,uint8_t f,int32_t id,
                   const uint8_t*d,size_t l,void*u){
    (void)s;(void)f;(void)id;(void)d; ((h2x_t*)u)->rx+=(long)l; return 0; }

static int h2_do(conn_t *c, SSL_CTX *c1, SSL_CTX *c2)
{
    if (!conn_ok(c) || !c->is_h2) {
        conn_kill(c);
        if (conn_open(c, c1, c2) < 0) return -1;
        if (!c->is_h2) return -2;
    }

    const int NS = H2_STREAMS_PER_CONN;
    h2x_t hx = {c->ssl, 0, NS, 0, 0};

    nghttp2_session_callbacks *cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_send_callback(cb, _h2send);
    nghttp2_session_callbacks_set_recv_callback(cb, _h2recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, _h2close);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, _h2data);

    nghttp2_session *sess = NULL;
    nghttp2_session_client_new(&sess, cb, &hx);
    nghttp2_session_callbacks_del(cb);

    /* Buyuk window = sunucu daha fazla data gonderebilir */
    nghttp2_settings_entry iv[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, (uint32_t)NS},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,    1<<20},
    };
    nghttp2_submit_settings(sess, NGHTTP2_FLAG_NONE, iv, 2);
    /* Connection-level window da artir */
    nghttp2_submit_window_update(sess, NGHTTP2_FLAG_NONE, 0, (1<<30)-(1<<16));

    static __thread char auth[MAX_HOST+8];
    static __thread int  auth_init = 0;
    if (!auth_init) {
        snprintf(auth, sizeof(auth), "%s:%d", G.host, G.port);
        auth_init = 1;
    }
    size_t alen = strlen(auth);

    nghttp2_nv hdrs[] = {
        {(uint8_t*)":method",    (uint8_t*)"GET",   7, 3,    NGHTTP2_NV_FLAG_NONE},
        {(uint8_t*)":path",      (uint8_t*)"/",     5, 1,    NGHTTP2_NV_FLAG_NONE},
        {(uint8_t*)":scheme",    (uint8_t*)"https", 7, 5,    NGHTTP2_NV_FLAG_NONE},
        {(uint8_t*)":authority", (uint8_t*)auth,   10, alen, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t*)"user-agent", (uint8_t*)"ts/5", 10, 4,   NGHTTP2_NV_FLAG_NONE},
    };

    for (int i = 0; i < NS; i++)
        nghttp2_submit_request(sess, NULL, hdrs, 5, NULL, NULL);

    int rv = 0;
    while (hx.done < NS && g_run) {
        rv = nghttp2_session_send(sess);
        if (rv) break;
        rv = nghttp2_session_recv(sess);
        if (rv) break;
    }

    int ok = hx.done - hx.errs;
    atomic_fetch_add(&g_bytes, hx.rx);
    c->uses += NS;
    nghttp2_session_del(sess);
    if (c->uses >= CONN_MAX_REUSE) conn_kill(c);
    return ok > 0 ? ok : -1;
}

/* ================================================================
 *  Worker thread
 *  - CONNS_PER_THREAD baglanti, round-robin dispatch
 *  - Her iterasyonda TUM baglantilar siraya girer
 *  - Batch atomic update ile log overhead sifir
 * ================================================================ */
typedef struct { SSL_CTX *c1, *c2; int id; } warg_t;

static void *worker(void *arg)
{
    warg_t *a = (warg_t*)arg;

    bucket_t bkt;
    bucket_init(&bkt, G.rps_per_thread);

    conn_t pool[CONNS_PER_THREAD];
    memset(pool, 0, sizeof(pool));
    for (int i = 0; i < CONNS_PER_THREAD; i++) pool[i].fd = -1;

    long local_ok = 0, local_fail = 0, local_bytes = 0;
    int  flush_ctr = 0;
    int  ci = 0;

    while (g_run) {
        conn_t *c = &pool[ci % CONNS_PER_THREAD];
        ci++;

        int rc;
        int batch;

        switch (G.proto) {
        case PROTO_HTTP2:
            batch = H2_STREAMS_PER_CONN;
            bucket_wait(&bkt, batch);
            rc = h2_do(c, a->c1, a->c2);
            if (rc == -2) { conn_kill(c);
                batch = H1_PIPELINE_DEPTH;
                rc = h1_do(c, a->c1, a->c2); }
            break;
        case PROTO_HTTP1:
            batch = H1_PIPELINE_DEPTH;
            bucket_wait(&bkt, batch);
            rc = h1_do(c, a->c1, a->c2);
            break;
        default: /* AUTO */
            batch = H2_STREAMS_PER_CONN;
            bucket_wait(&bkt, batch);
            rc = h2_do(c, a->c1, a->c2);
            if (rc < 0) {
                conn_kill(c);
                batch = H1_PIPELINE_DEPTH;
                rc = h1_do(c, a->c1, a->c2);
            }
            break;
        }

        if (rc > 0) local_ok += rc;
        else        local_fail++;

        /* Her 256 iterasyonda bir atomic guncelle — overhead minimun */
        if (++flush_ctr >= 256) {
            atomic_fetch_add(&g_ok,   local_ok);
            atomic_fetch_add(&g_fail, local_fail);
            local_ok = local_fail = 0;
            flush_ctr = 0;
        }
    }

    /* Son flush */
    atomic_fetch_add(&g_ok,    local_ok);
    atomic_fetch_add(&g_fail,  local_fail);
    atomic_fetch_add(&g_bytes, local_bytes);

    for (int i = 0; i < CONNS_PER_THREAD; i++) conn_kill(&pool[i]);
    return NULL;
}

/* ================================================================
 *  Timer
 * ================================================================ */
static void *timer_fn(void *a)
{
    (void)a; sleep(G.duration); g_run = 0; return NULL;
}

/* ================================================================
 *  main
 * ================================================================ */
int main(int argc, char *argv[])
{
    if (argc < 6) {
        fprintf(stderr,
            "\nKullanim: %s <host> <port> <sure> <thread> <rps_per_thread> [proto] [tls]\n"
            "  rps=0    -> sinirsiz\n"
            "  proto    -> auto|h1|h2\n"
            "  tls      -> tls12|tls13\n\n"
            "Ornekler:\n"
            "  %s target.com 443 60 20 0           # tam hiz\n"
            "  %s target.com 443 60 20 1000 h2      # 20x1000=20k rps\n\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    strncpy(G.host, argv[1], MAX_HOST-1);
    G.port           = atoi(argv[2]);
    G.duration       = atoi(argv[3]);
    G.nthread        = atoi(argv[4]);
    G.rps_per_thread = atol(argv[5]);
    G.proto = PROTO_AUTO; G.tls_ver = TLS_AUTO;

    for (int i=6; i<argc; i++) {
        if      (!strcmp(argv[i],"h1"))    G.proto   = PROTO_HTTP1;
        else if (!strcmp(argv[i],"h2"))    G.proto   = PROTO_HTTP2;
        else if (!strcmp(argv[i],"tls12")) G.tls_ver = TLS_V12;
        else if (!strcmp(argv[i],"tls13")) G.tls_ver = TLS_V13;
    }

    if (G.port<=0||G.port>65535){ fputs("port?\n",stderr); return 1; }
    if (G.duration<=0)           { fputs("sure?\n",stderr); return 1; }
    if (G.nthread<=0||G.nthread>4096){ fputs("thread 1-4096\n",stderr); return 1; }

    if (dns_resolve()) { fprintf(stderr,"DNS fail: %s\n",G.host); return 1; }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *c1 = make_ctx(0), *c2 = make_ctx(1);
    if (!c1||!c2){ fputs("SSL_CTX fail\n",stderr); return 1; }

    /* ---- BASLIK ---- */
    const char *pstr = G.proto==PROTO_HTTP1 ? "HTTP/1.1 pipeline"
                     : G.proto==PROTO_HTTP2 ? "HTTP/2 mux"
                     : "AUTO";
    const char *tstr = G.tls_ver==TLS_V12 ? "TLS1.2"
                     : G.tls_ver==TLS_V13 ? "TLS1.3" : "TLS1.2+";
    char rstr[32];
    if (G.rps_per_thread>0)
         snprintf(rstr,sizeof(rstr),"%ld/thread = %ld total",
                  G.rps_per_thread, G.rps_per_thread*G.nthread);
    else snprintf(rstr,sizeof(rstr),"UNLIMITED");

    printf("\n+----------------------------------------------------------+\n");
    printf("| TLS Stress v5.0                                          |\n");
    printf("+----------------------------------------------------------+\n");
    printf("| Host     : %-45s|\n", G.host);
    printf("| Port     : %-45d|\n", G.port);
    printf("| Duration : %-42d sn  |\n", G.duration);
    printf("| Threads  : %-45d|\n", G.nthread);
    printf("| RPS      : %-45s|\n", rstr);
    printf("| Protocol : %-45s|\n", pstr);
    printf("| TLS      : %-45s|\n", tstr);
    printf("| Conns/T  : %-45d|\n", CONNS_PER_THREAD);
    printf("| H2 Str   : %-45d|\n", H2_STREAMS_PER_CONN);
    printf("| H1 Pipe  : %-45d|\n", H1_PIPELINE_DEPTH);
    printf("+----------------------------------------------------------+\n\n");

    printf(" %5s  %10s  %10s  %12s  %10s\n",
           "t(s)", "ok", "fail", "RPS", "MB");
    printf(" ─────────────────────────────────────────────────────────\n");

    pthread_t tmr;
    pthread_create(&tmr, NULL, timer_fn, NULL);

    warg_t   *wa  = calloc(G.nthread, sizeof(warg_t));
    pthread_t *td = calloc(G.nthread, sizeof(pthread_t));

    struct timespec ts0, tsp, tsn;
    clock_gettime(CLOCK_MONOTONIC, &ts0); tsp = ts0;

    for (int i=0; i<G.nthread; i++) {
        wa[i].c1=c1; wa[i].c2=c2; wa[i].id=i;
        pthread_create(&td[i], NULL, worker, &wa[i]);
    }

    long po=0, pf=0;
    for (int s=1; s<=G.duration; s++) {
        sleep(1);
        clock_gettime(CLOCK_MONOTONIC, &tsn);
        double dt = (tsn.tv_sec-tsp.tv_sec)+(tsn.tv_nsec-tsp.tv_nsec)/1e9;
        tsp = tsn;

        long co = atomic_load(&g_ok);
        long cf = atomic_load(&g_fail);
        long cb = atomic_load(&g_bytes);
        long dok = co-po, dfail = cf-pf;
        po=co; pf=cf;

        double rps = dt>0 ? (double)(dok+dfail)/dt : 0;
        double mb  = (double)cb/(1024.0*1024.0);

        printf(" %5d  %10ld  %10ld  %12.0f  %10.1f\n",
               s, co, cf, rps, mb);
        fflush(stdout);
    }

    g_run = 0;
    for (int i=0; i<G.nthread; i++) pthread_join(td[i], NULL);
    pthread_join(tmr, NULL);

    clock_gettime(CLOCK_MONOTONIC, &tsn);
    double el = (tsn.tv_sec-ts0.tv_sec)+(tsn.tv_nsec-ts0.tv_nsec)/1e9;
    long tot_ok   = atomic_load(&g_ok);
    long tot_fail = atomic_load(&g_fail);
    long tot      = tot_ok+tot_fail;
    double mb     = (double)atomic_load(&g_bytes)/(1024.0*1024.0);

    printf("\n+----------------------------------------------------------+\n");
    printf("| SONUC                                                    |\n");
    printf("+----------------------------------------------------------+\n");
    printf("| Sure      : %-44.2f sn |\n", el);
    printf("| Toplam    : %-44ld |\n", tot);
    printf("| Basarili  : %-44ld |\n", tot_ok);
    printf("| Fail      : %-44ld |\n", tot_fail);
    printf("| Ort RPS   : %-43.0f   |\n", el>0?(double)tot/el:0);
    printf("| Veri      : %-41.1f MB   |\n", mb);
    printf("+----------------------------------------------------------+\n\n");

    SSL_CTX_free(c1); SSL_CTX_free(c2);
    free(wa); free(td);
    return 0;
}
