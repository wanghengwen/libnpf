/* The signaling connections' state machine (src/node/sigconn.c,
 * signaling-udp.md 5.3), one event at a time, on a fake clock and handles
 * with nothing behind them: UDP first and the WebSocket a second later; the
 * WebSocket winning with UDP silent (udp_bad) or slower (not); UDP failing
 * before the WebSocket's turn (it at once); the server busy over UDP; no
 * login over UDP in 20 s; on the WebSocket alone the second access point
 * going on when the first fails, and failing itself; the move to UDP:
 * taken, refused, failed, the WebSocket closed by the server before the UDP
 * welcome, the WebSocket dropping while UDP logs in, the old WebSocket
 * closed after 10 s; "replaced" counting only when it is not the move's;
 * a drop closing everything; events of unknown connections ignored. */
#include <string.h>

#include "node_internal.h"
#include "test.h"

static npf_sigc m;
static char h[4];                       /* the handles: their addresses */
#define U  ((npf_sig *)&h[0])           /* UDP */
#define W  ((npf_sig *)&h[1])           /* a WebSocket */
#define W2 ((npf_sig *)&h[2])           /* another */
#define X  ((npf_sig *)&h[3])           /* none of the machine's */
static npf_sig *closed[8];
static int nclosed;

static void fake_close(npf_sig *s)
{
    if (nclosed < 8)
        closed[nclosed++] = s;
}

static int was_closed(npf_sig *s)
{
    int i;
    for (i = 0; i < nclosed; i++)
        if (closed[i] == s)
            return 1;
    return 0;
}

static void fresh(void)
{
    memset(&m, 0, sizeof m);
    m.close = fake_close;
    nclosed = 0;
}

/* online at t on the WebSocket alone (server 0, URL 0) */
static void online_ws(int64_t t)
{
    sc_start(&m, W, 0, 0, 0, t);
    EXPECT(sc_ready(&m, SR_MAIN, 0) == SA_FIRST);
    EXPECT(sc_login(&m, SR_MAIN, 1, t) == SA_WELCOME && m.state == SS_ONLINE);
}

/* ... and moving: the move due, MOVE (UDP) opened and its handshake done */
static void moving(int64_t t)
{
    online_ws(t);
    m.move_at = t + 600;                /* the node's move_arm */
    EXPECT(sc_tick(&m, t + 599) == SA_NONE);
    EXPECT(sc_tick(&m, t + 600) == SA_MOVE_DUE);
    sc_open(&m, SR_MOVE, U, 0, -1);
    EXPECT(m.state == SS_MOVE && sc_role(&m, U) == SR_MOVE);
    EXPECT(sc_ready(&m, SR_MOVE, 0) == SA_MOVE_LOGIN);
}

static void race(void)
{
    /* UDP answers within the second: no WebSocket, nothing closed */
    fresh();
    sc_start(&m, U, 0, 1, 1, 1000);
    EXPECT(m.state == SS_CONNECT && m.udp_silent == 0 && sc_next(&m) == 2000 && !m.c[SR_RACE].s);
    EXPECT(sc_ready(&m, SR_MAIN, 1) == SA_FIRST && m.race_at == 0 && nclosed == 0);
    EXPECT(sc_tick(&m, 2000) == SA_NONE);
    EXPECT(sc_login(&m, SR_MAIN, 1, 2000) == SA_WELCOME && m.state == SS_ONLINE && !m.udp_bad && !m.login_at);

    /* UDP after the WebSocket opened: UDP stays, the WebSocket closed */
    fresh();
    sc_start(&m, U, 0, 1, 1, 0);
    EXPECT(sc_tick(&m, 999) == SA_NONE && sc_tick(&m, 1000) == SA_OPEN_RACE);
    EXPECT(m.c[SR_RACE].server == 0 && m.c[SR_RACE].url == 1);
    m.c[SR_RACE].s = W;                 /* the node opened it */
    EXPECT(sc_ready(&m, SR_MAIN, 1) == SA_FIRST && was_closed(W) && !m.c[SR_RACE].s);

    /* the WebSocket first, UDP silent: udp_bad at its welcome */
    fresh();
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_tick(&m, 1000) == SA_OPEN_RACE);
    m.c[SR_RACE].s = W;
    EXPECT(sc_ready(&m, SR_RACE, 0) == SA_RACE_WON && was_closed(U) && m.c[SR_MAIN].s == W);
    EXPECT(m.c[SR_MAIN].url == 0 && m.udp_silent == 1 && !m.udp_bad);
    EXPECT(sc_login(&m, SR_MAIN, 1, 1500) == (SA_WELCOME | SA_UDP_BAD) && m.udp_bad == 1);

    /* ... UDP answered, only slower: no udp_bad */
    fresh();
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_tick(&m, 1000) == SA_OPEN_RACE);
    m.c[SR_RACE].s = W;
    EXPECT(sc_ready(&m, SR_RACE, 1) == SA_RACE_WON && m.udp_silent == 0);
    EXPECT(sc_login(&m, SR_MAIN, 1, 1500) == SA_WELCOME && !m.udp_bad);

    /* UDP fails before the WebSocket's turn: it now, as MAIN; udp_bad at its welcome */
    fresh();
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_down(&m, SR_MAIN, 0, 0, 300) == SA_WS_NOW);
    EXPECT(!m.c[SR_MAIN].s && m.c[SR_MAIN].url == 0 && m.race_at == 0 && m.state == SS_CONNECT && !was_closed(U));
    m.c[SR_MAIN].s = W;
    EXPECT(sc_ready(&m, SR_MAIN, 0) == SA_FIRST);
    EXPECT(sc_login(&m, SR_MAIN, 1, 500) == (SA_WELCOME | SA_UDP_BAD));

    /* the server too busy for the UDP session: udp_bad at once, the WebSocket now */
    fresh();
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_down(&m, SR_MAIN, 1, 1, 300) == (SA_WS_NOW | SA_UDP_BAD) && m.udp_bad == 1);
    m.c[SR_MAIN].s = W;
    EXPECT(sc_ready(&m, SR_MAIN, 0) == SA_FIRST && sc_login(&m, SR_MAIN, 1, 500) == SA_WELCOME);
    /* ... after the WebSocket opened: it goes on */
    fresh();
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_tick(&m, 1000) == SA_OPEN_RACE);
    m.c[SR_RACE].s = W;
    EXPECT(sc_down(&m, SR_MAIN, 1, 1, 1200) == (SA_TO_RACE | SA_UDP_BAD) && m.c[SR_MAIN].s == W);
    /* ... and udp_bad set already: no second time */
    fresh();
    m.udp_bad = 1;
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_down(&m, SR_MAIN, 1, 1, 300) == SA_WS_NOW);

    /* the UDP handshake, no login in 20 s: udp_bad, aborted */
    fresh();
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_ready(&m, SR_MAIN, 1) == SA_FIRST);
    EXPECT(sc_tick(&m, 19999) == SA_NONE && sc_next(&m) == 20000);
    EXPECT(sc_tick(&m, 20000) == (SA_LATE | SA_UDP_BAD) && m.udp_bad == 1);
    EXPECT(sc_abort(&m, 1, 20000) == SA_GONE && m.state == SS_IDLE && !m.c[SR_MAIN].s && !was_closed(U));
    EXPECT(sc_next(&m) == 0);
    /* ... on the WebSocket: aborted, nothing on UDP */
    fresh();
    sc_start(&m, W, 0, 0, 0, 0);
    EXPECT(sc_tick(&m, 20000) == SA_LATE && !m.udp_bad);
    /* ... logged in: nothing due */
    fresh();
    online_ws(0);
    EXPECT(sc_tick(&m, 20000) == SA_NONE);

    /* the WebSocket alone with a second access point: the first fails, the
     * second goes on; the second fails, the first goes on; the second first */
    fresh();
    sc_start(&m, W, 0, 0, 0, 0);
    sc_open(&m, SR_RACE, W2, 1, 0);
    EXPECT(m.udp_silent == -1 && m.state == SS_CONNECT);
    EXPECT(sc_down(&m, SR_MAIN, 0, 0, 100) == SA_TO_RACE && m.c[SR_MAIN].s == W2 && m.c[SR_MAIN].server == 1);
    EXPECT(!m.c[SR_RACE].s && sc_ready(&m, SR_MAIN, 0) == SA_FIRST);
    EXPECT(sc_login(&m, SR_MAIN, 1, 200) == SA_WELCOME && !m.udp_bad);
    fresh();
    sc_start(&m, W, 0, 0, 0, 0);
    sc_open(&m, SR_RACE, W2, 1, 0);
    EXPECT(sc_down(&m, SR_RACE, 0, 0, 100) == SA_RACE_FAILED && m.c[SR_RACE].server == 1 && m.c[SR_MAIN].s == W);
    EXPECT(sc_down(&m, SR_MAIN, 0, 0, 200) == SA_GONE && m.state == SS_IDLE);
    fresh();
    sc_start(&m, W, 0, 0, 0, 0);
    sc_open(&m, SR_RACE, W2, 1, 0);
    EXPECT(sc_ready(&m, SR_RACE, 0) == SA_RACE_WON && was_closed(W) && m.c[SR_MAIN].s == W2);
    EXPECT(sc_role(&m, W) == -1 && sc_ready(&m, sc_role(&m, W), 0) == SA_NONE);   /* the one closed */
}

static void move(void)
{
    /* taken: the server's "replaced" on the WebSocket is not counted, the
     * UDP welcome moves (no new login), the WebSocket kept until it closes */
    fresh();
    moving(0);
    EXPECT(sc_replaced(&m, SR_MAIN) == 0 && m.state == SS_TAKEN);
    EXPECT(sc_replaced(&m, SR_MAIN) == 0);
    EXPECT(sc_login(&m, SR_MOVE, 1, 1000) == SA_MOVED && m.state == SS_ONLINE);
    EXPECT(m.c[SR_MAIN].s == U && m.c[SR_OLD].s == W && m.old_at == 11000 && !m.c[SR_MOVE].s && nclosed == 0);
    EXPECT(sc_replaced(&m, SR_OLD) == 0);
    EXPECT(sc_down(&m, SR_OLD, 1, 0, 1200) == SA_OLD_CLOSED && !m.c[SR_OLD].s && !m.old_at && !was_closed(W));
    EXPECT(sc_replaced(&m, SR_MAIN) == 1);      /* on UDP now: another login of this identity */
    /* ... the server does not close it: we do after 10 s */
    fresh();
    moving(0);
    EXPECT(sc_login(&m, SR_MOVE, 1, 1000) == SA_MOVED);
    EXPECT(sc_tick(&m, 10999) == SA_NONE && sc_tick(&m, 11000) == SA_OLD_CLOSED && was_closed(W));
    /* ... it was udp_bad: no more */
    fresh();
    m.udp_bad = 1;
    moving(0);
    EXPECT(sc_login(&m, SR_MOVE, 1, 1000) == SA_MOVED && !m.udp_bad);

    /* refused: on the WebSocket, the UDP session closed */
    fresh();
    moving(0);
    EXPECT(sc_login(&m, SR_MOVE, 0, 1000) == SA_MOVE_FAILED && m.state == SS_ONLINE && was_closed(U));
    EXPECT(m.c[SR_MAIN].s == W && !m.c[SR_MOVE].s);
    /* failed: likewise */
    fresh();
    moving(0);
    EXPECT(sc_down(&m, SR_MOVE, 0, 0, 1000) == SA_MOVE_FAILED && m.state == SS_ONLINE && !was_closed(U));
    EXPECT(m.c[SR_MAIN].s == W && !m.c[SR_MOVE].s && sc_login(&m, SR_MOVE, 1, 1100) == SA_NONE);
    /* not due on UDP, nor while moving */
    fresh();
    sc_start(&m, U, 0, 0, 1, 0);
    EXPECT(sc_ready(&m, SR_MAIN, 1) == SA_FIRST && sc_login(&m, SR_MAIN, 1, 0) == SA_WELCOME);
    m.move_at = 600;
    EXPECT(sc_tick(&m, 600) == SA_NONE);

    /* the server closed the replaced WebSocket before the UDP welcome came:
     * the move all the same, no drop, no new login */
    fresh();
    moving(0);
    EXPECT(sc_replaced(&m, SR_MAIN) == 0);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 1000) == SA_TAKEN && m.state == SS_WELCOME && m.c[SR_MAIN].s == U);
    EXPECT(!m.c[SR_MOVE].s && !was_closed(W) && !m.login_at);
    EXPECT(sc_login(&m, SR_MAIN, 1, 1200) == SA_MOVED && m.state == SS_ONLINE && !m.c[SR_OLD].s);
    /* ... refused after all: as any login */
    fresh();
    moving(0);
    sc_replaced(&m, SR_MAIN);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 1000) == SA_TAKEN && sc_login(&m, SR_MAIN, 0, 1200) == SA_REFUSED);
    /* ... gone instead: a drop */
    fresh();
    moving(0);
    sc_replaced(&m, SR_MAIN);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 1000) == SA_TAKEN && sc_down(&m, SR_MAIN, 1, 0, 1100) == SA_GONE);

    /* the WebSocket dropped while UDP logs in (no "replaced"): offline, UDP
     * goes on as MAIN with a login deadline of its own; its welcome a login */
    fresh();
    moving(0);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 1000) == SA_UDP_GOES_ON && m.state == SS_CONNECT);
    EXPECT(m.c[SR_MAIN].s == U && !m.c[SR_MOVE].s && m.login_at == 21000 && !was_closed(W));
    EXPECT(sc_login(&m, SR_MAIN, 1, 1500) == SA_WELCOME && m.state == SS_ONLINE && !m.login_at);
    /* ... its handshake still to come: then it logs in as the first */
    fresh();
    online_ws(0);
    sc_open(&m, SR_MOVE, U, 0, -1);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 1000) == SA_UDP_GOES_ON && sc_ready(&m, SR_MAIN, 0) == SA_FIRST);
    /* ... or it fails too: gone */
    fresh();
    moving(0);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 1000) == SA_UDP_GOES_ON);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 2000) == SA_GONE && m.state == SS_IDLE);
    /* ... or no login in time */
    fresh();
    moving(0);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 1000) == SA_UDP_GOES_ON);
    EXPECT(sc_tick(&m, 20999) == SA_NONE && sc_tick(&m, 21000) == (SA_LATE | SA_UDP_BAD));
    /* ... aborted while moving (the watch): likewise */
    fresh();
    moving(0);
    EXPECT(sc_abort(&m, 1, 1000) == SA_UDP_GOES_ON && m.c[SR_MAIN].s == U);
}

static void other(void)
{
    /* a drop online: everything closed (the old WebSocket too), nothing due */
    fresh();
    moving(0);
    EXPECT(sc_login(&m, SR_MOVE, 1, 1000) == SA_MOVED);
    EXPECT(sc_down(&m, SR_MAIN, 1, 0, 2000) == SA_GONE && m.state == SS_IDLE && was_closed(W) && !was_closed(U));
    EXPECT(!m.c[SR_OLD].s && sc_next(&m) == 0);
    /* "replaced" on the connection in use counts; refused: the node's */
    fresh();
    online_ws(0);
    EXPECT(sc_replaced(&m, SR_MAIN) == 1 && sc_login(&m, SR_MAIN, 0, 0) == SA_REFUSED);
    /* events of connections not the machine's: nothing */
    EXPECT(sc_role(&m, X) == -1 && sc_role(&m, NULL) == SR_MAIN && sc_role(&m, W) == SR_MAIN);
    EXPECT(sc_down(&m, -1, 0, 0, 0) == SA_NONE && sc_ready(&m, -1, 0) == SA_NONE);
    EXPECT(sc_login(&m, -1, 1, 0) == SA_NONE && sc_replaced(&m, -1) == 0);
    EXPECT(m.state == SS_ONLINE && m.c[SR_MAIN].s == W);
    /* closed: all of them, the flags kept */
    m.udp_bad = 1;
    sc_open(&m, SR_OLD, W2, 0, 0);
    sc_close(&m);
    EXPECT(m.state == SS_IDLE && was_closed(W) && was_closed(W2) && m.udp_bad == 1 && sc_next(&m) == 0);
}

int test_sigconn(void)
{
    race();
    move();
    other();
    return fails;
}
