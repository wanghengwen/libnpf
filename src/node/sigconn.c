/* The node's signaling connections as a state machine (signaling-udp.md
 * 5.3; the roles and states: npf/node.h npf_sigc). UDP first and the
 * WebSocket of the same server a second later (at once when UDP fails
 * first), the first handshake done stays; on the WebSocket alone a second
 * access point beside it (security.md 7.5); on the WebSocket every 10 min a
 * UDP session logs in and takes over. One function per event: it moves the
 * connections between the roles, sets the state, udp_bad and the times due,
 * and returns what the node does (SA_*). Nothing here but closing what the
 * machine drops: the node (node_signal.c) opens the connections, logs and
 * keeps the time; the unit test (test_sigconn.c) feeds the events alone. */
#include "node_internal.h"

static void drop(npf_sigc *m, int r)
{
    npf_sig *s = m->c[r].s;
    m->c[r].s = NULL;
    if (s)
        (m->close ? m->close : npf_sig_close)(s);
}

/* r takes MAIN's place (MAIN's connection gone, or dropped) */
static void promote(npf_sigc *m, int r)
{
    m->c[SR_MAIN] = m->c[r];
    m->c[r].s = NULL;
}

static int is_udp(const npf_sigc *m) { return m->c[SR_MAIN].url < 0; }

int sc_role(const npf_sigc *m, const npf_sig *s)
{
    int r;
    if (!s)
        return SR_MAIN;                 /* a message handed in without a connection (tests) */
    for (r = 0; r < SR_N; r++)
        if (m->c[r].s == s)
            return r;
    return -1;
}

void sc_start(npf_sigc *m, npf_sig *s, int server, int url, int udp, int64_t now)
{
    sc_close(m);
    m->c[SR_MAIN] = (npf_sigconn){s, server, udp ? -1 : url};
    m->state = SS_CONNECT;
    m->udp_silent = udp ? 0 : -1;
    m->login_at = now + SIG_LOGIN_MS;
    if (udp) {                          /* the server's WebSocket a second later */
        m->c[SR_RACE] = (npf_sigconn){NULL, server, url};
        m->race_at = now + SIG_WS_AFTER_MS;
    }
}

void sc_open(npf_sigc *m, int r, npf_sig *s, int server, int url)
{
    m->c[r] = (npf_sigconn){s, server, url};
    if (r == SR_MOVE)
        m->state = SS_MOVE;
}

void sc_close(npf_sigc *m)
{
    int r;
    for (r = 0; r < SR_N; r++)
        drop(m, r);
    m->state = SS_IDLE;
    m->race_at = m->login_at = m->move_at = m->old_at = 0;
}

/* heard: MAIN (on UDP) has heard from its server */
int sc_ready(npf_sigc *m, int r, int heard)
{
    if (r == SR_MOVE)
        return SA_MOVE_LOGIN;
    if (m->state != SS_CONNECT || (r != SR_MAIN && r != SR_RACE))
        return SA_NONE;
    m->race_at = 0;
    if (r == SR_MAIN) {
        drop(m, SR_RACE);
        return SA_FIRST;
    }
    if (is_udp(m) && !heard)
        m->udp_silent = 1;
    drop(m, SR_MAIN);
    promote(m, SR_RACE);
    return SA_RACE_WON;
}

/* heard: r's connection heard from its server; busy: the server was too
 * busy for it (UDP's CLOSE "busy") */
int sc_down(npf_sigc *m, int r, int heard, int busy, int64_t now)
{
    int a = 0;
    switch (r) {
    case SR_OLD:
        m->c[SR_OLD].s = NULL;
        m->old_at = 0;
        return SA_OLD_CLOSED;
    case SR_MOVE:
        m->c[SR_MOVE].s = NULL;
        m->state = SS_ONLINE;
        return SA_MOVE_FAILED;
    case SR_RACE:
        m->c[SR_RACE].s = NULL;
        return SA_RACE_FAILED;
    case SR_MAIN:
        break;
    default:
        return SA_NONE;
    }
    m->c[SR_MAIN].s = NULL;
    switch (m->state) {
    case SS_MOVE:                       /* the WebSocket went while UDP logs in: UDP goes on */
        promote(m, SR_MOVE);
        m->state = SS_CONNECT;
        m->login_at = now + SIG_LOGIN_MS;
        return SA_UDP_GOES_ON;
    case SS_TAKEN:                      /* the server closed the WebSocket it replaced: the move */
        promote(m, SR_MOVE);
        m->state = SS_WELCOME;
        return SA_TAKEN;
    case SS_CONNECT:
        if (is_udp(m) && !heard)        /* UDP over before its login */
            m->udp_silent = 1;
        else if (is_udp(m) && busy && !m->udp_bad)
            m->udp_bad = 1, a = SA_UDP_BAD;
        if (m->race_at) {               /* before the WebSocket's turn: it now */
            m->race_at = 0;
            promote(m, SR_RACE);
            return a | SA_WS_NOW;
        }
        if (m->c[SR_RACE].s) {          /* the second goes on */
            promote(m, SR_RACE);
            return a | SA_TO_RACE;
        }
        break;
    }
    sc_close(m);
    return a | SA_GONE;
}

int sc_abort(npf_sigc *m, int heard, int64_t now)
{
    drop(m, SR_RACE);
    m->race_at = 0;
    return sc_down(m, SR_MAIN, heard, 0, now);
}

int sc_login(npf_sigc *m, int r, int ok, int64_t now)
{
    int a = SA_WELCOME;
    if (r == SR_MOVE && (m->state == SS_MOVE || m->state == SS_TAKEN)) {
        if (!ok) {
            drop(m, SR_MOVE);
            m->state = SS_ONLINE;
            return SA_MOVE_FAILED;
        }
        drop(m, SR_OLD);                /* the server's to close, else ours in 10 s */
        m->c[SR_OLD] = m->c[SR_MAIN];
        promote(m, SR_MOVE);
        m->old_at = now + SIG_OLD_MS;
        a = SA_MOVED;
    } else if (r != SR_MAIN) {
        return SA_NONE;
    } else if (!ok) {
        return SA_REFUSED;
    } else if (m->state == SS_WELCOME) {
        a = SA_MOVED;
    }
    if (a == SA_MOVED || m->state == SS_CONNECT)
        m->state = SS_ONLINE;
    m->login_at = 0;
    if (is_udp(m))
        m->udp_bad = 0;
    else if (m->udp_silent == 1 && !m->udp_bad)
        m->udp_bad = 1, a |= SA_UDP_BAD;
    return a;
}

/* "replaced" on r: 1 when it counts (the identity logged in elsewhere), 0
 * when it is our move's doing or not on MAIN */
int sc_replaced(npf_sigc *m, int r)
{
    if (r != SR_MAIN)
        return 0;
    if (m->state != SS_MOVE && m->state != SS_TAKEN)
        return 1;
    m->state = SS_TAKEN;
    return 0;
}

static int due(int64_t *at, int64_t now)
{
    if (!*at || *at > now)
        return 0;
    *at = 0;
    return 1;
}

int sc_tick(npf_sigc *m, int64_t now)
{
    if (due(&m->race_at, now))
        return SA_OPEN_RACE;
    if (due(&m->login_at, now) && m->state == SS_CONNECT) {
        if (is_udp(m) && !m->udp_bad)   /* its handshake came, its login did not: not again */
            return m->udp_bad = 1, SA_LATE | SA_UDP_BAD;
        return SA_LATE;
    }
    if (due(&m->move_at, now) && m->state == SS_ONLINE && !is_udp(m))
        return SA_MOVE_DUE;
    if (due(&m->old_at, now)) {
        drop(m, SR_OLD);
        return SA_OLD_CLOSED;
    }
    return SA_NONE;
}

int64_t sc_next(const npf_sigc *m)
{
    const int64_t *t[] = {&m->race_at, &m->login_at, &m->move_at, &m->old_at};
    int64_t at = 0;
    size_t i;
    for (i = 0; i < sizeof t / sizeof t[0]; i++)
        if (*t[i] && (!at || *t[i] < at))
            at = *t[i];
    return at;
}
