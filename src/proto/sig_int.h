/* The signaling connection's two carriers (npf/sig.h): WebSocket (sig.c)
 * and UDP (sigudp.c, signaling-udp.md), behind one table. Private to
 * src/proto. */
#ifndef NPF_SIG_INT_H
#define NPF_SIG_INT_H

#include "npf/noise.h"
#include "npf/sig.h"
#include "npf/ws.h"

/* what a carrier does (input and bye may be NULL); npf_sig's public calls
 * check dead and ready first */
typedef struct sig_ops {
    const char *via;
    int         (*send_json)(npf_sig *s, const char *json, size_t len);  /* not "send": Winsock's macro */
    int         (*ping)(npf_sig *s);
    int64_t     (*last_rx)(const npf_sig *s);
    int         (*rtt)(const npf_sig *s);
    const char *(*diag)(const npf_sig *s, char *buf, size_t cap);    /* NULL: no connection */
    int         (*input)(npf_sig *s, const struct sockaddr_storage *from, const uint8_t *buf, size_t len);
    void        (*bye)(npf_sig *s);              /* closed by the caller: tell the server */
    void        (*release)(npf_sig *s);          /* the carrier's state, wiped */
} sig_ops;

struct npf_sig {
    const sig_ops *ops;
    npf_sig_cbs    cbs;
    void          *arg;
    uint8_t        hash[64];
    int64_t        last_tx;             /* monotonic ms of our last message or ping, 0 = none */
    int            ready;
    int            depth, dead;         /* callbacks of s running; down or closed (freed at depth 0) */
    /* WebSocket */
    npf_ws        *ws;
    npf_noise_hs   hs;
    npf_noise_cs   tx, rx;
    /* UDP */
    struct sigudp *udp;
};

/* around every callback from the loop: s is freed when the outermost one
 * that finds it dead returns */
void sig_enter(npf_sig *s);
void sig_leave(npf_sig *s);
/* the connection is over: on_down once */
void sig_down(npf_sig *s, npf_sig_down code, const char *why);
/* a whole message received (plaintext JSON) to on_msg: NULL when handed
 * over, else why not */
const char *sig_json(npf_sig *s, const uint8_t *plain, size_t len);

#endif
