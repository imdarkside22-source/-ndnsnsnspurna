#ifndef ATTACK_H
#define ATTACK_H

/*
 * attack.h — L4 flood method bildirimleri
 *
 * Her method imzasi:
 *   void start_<method>(const char *host, int port,
 *                        int duration, int threads, int rps);
 *
 * rps == 0  →  throttle uygulanmaz, maksimum hiz.
 * GRE flood'da port parametresi kabul edilir fakat kullanilmaz.
 */

/* UDP flood (snorlax) */
void start_udpflood(const char *host, int port, int duration, int threads, int rps);

/* TCP connect flood (gengar) */
void start_tcpflood(const char *host, int port, int duration, int threads, int rps);

/* TCP SYN flood — raw socket gerektirir (root/CAP_NET_RAW) (dragonite) */
void start_synflood(const char *host, int port, int duration, int threads, int rps);

/* TCP ACK flood — raw socket gerektirir (root/CAP_NET_RAW) (tyranitar) */
void start_ackflood(const char *host, int port, int duration, int threads, int rps);

/* GRE flood — raw socket gerektirir (root/CAP_NET_RAW) (metagross) */
void start_greflood(const char *host, int port, int duration, int threads, int rps);

/* DNS query flood (salamence) */
void start_dnsflood(const char *host, int port, int duration, int threads, int rps);

#endif /* ATTACK_H */

