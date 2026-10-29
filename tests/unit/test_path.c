/* The path manager (path.h, architecture.md 2.4) over fake paths that
 * count what they are given: where pm_send sends (the primary path; a
 * direct path in doubt and the UDP relay both; the WS relay alone), the
 * roles, the name of the path in use, and npf.h's NPF_PATH_* for it. */
#include <stdio.h>
#include <string.h>

#include "npf.h"
#include "path.h"
#include "test.h"

typedef struct fake {
    npf_path p;
    int      sent;
    size_t   bytes;
} fake;

static void fake_send(npf_path *p, const uint8_t *dgram, size_t len)
{
    fake *f = (fake *)(void *)p;
    (void)dgram;
    f->sent++;
    f->bytes += len;
}

static const npf_path_ops fake_ops = {fake_send, NULL, NULL, NULL};

static fake f[PK_N];

static void reset(void)
{
    int k;
    for (k = 0; k < PK_N; k++)
        f[k].sent = 0, f[k].bytes = 0;
}

/* one datagram: which paths got it (a bit per kind) */
static int send1(npf_pm *m)
{
    static const uint8_t d[100];
    int k, got = 0;
    reset();
    pm_send(m, d, sizeof d);
    for (k = 0; k < PK_N; k++) {
        CHECK(f[k].sent <= 1 && f[k].bytes == (size_t)f[k].sent * sizeof d, "kind %d: %d datagrams", k, f[k].sent);
        got |= f[k].sent ? 1 << k : 0;
    }
    return got;
}

#define D (1 << PK_DIRECT)
#define U (1 << PK_UDP_RELAY)
#define W (1 << PK_WS_RELAY)

int test_path(void)
{
    npf_pm m;
    int k;
    memset(&m, 0, sizeof m);
    memset(f, 0, sizeof f);
    for (k = 0; k < PK_N; k++) {
        f[k].p.ops = &fake_ops;
        f[k].p.kind = (uint8_t)k;
        f[k].p.health = PH_UP;
    }
    CHECK(NPF_PATH_DIRECT == 1 + PK_DIRECT && NPF_PATH_UDP_RELAY == 1 + PK_UDP_RELAY
          && NPF_PATH_WS_RELAY == 1 + PK_WS_RELAY, "pm_code's 1 + kind is npf.h's NPF_PATH_*");

    /* no path: nothing sent, none named */
    CHECK(send1(&m) == 0 && !m.primary, "sent with no path");
    CHECK(strcmp(pm_name(&m), "none") == 0 && strcmp(pm_label(&m), "none") == 0 && pm_code(&m) == 0, "no path's name");

    /* the UDP relay alone carries the session */
    pm_add(&m, &f[PK_UDP_RELAY].p);
    CHECK(send1(&m) == U && f[PK_UDP_RELAY].p.role == PR_PRIMARY, "the UDP relay alone");
    CHECK(strcmp(pm_name(&m), "relay") == 0 && strcmp(pm_label(&m), "Relayed") == 0
          && pm_code(&m) == NPF_PATH_UDP_RELAY, "the UDP relay's name");
    for (k = PH_NEW; k <= PH_DEAD; k++) {      /* not bound (binding, probing, given up): its health says so */
        pm_health(&m, &f[PK_UDP_RELAY].p, k);
        CHECK(strcmp(pm_name(&m), k == PH_UP ? "relay" : "relay (binding)") == 0 && pm_code(&m) == NPF_PATH_UDP_RELAY,
              "the UDP relay's name, health %d: %s", k, pm_name(&m));
    }
    pm_health(&m, &f[PK_UDP_RELAY].p, PH_UP);

    /* a direct path comes: it carries the session, the relay stands by */
    pm_add(&m, &f[PK_DIRECT].p);
    CHECK(send1(&m) == D, "the direct path primary (%d)", send1(&m));
    CHECK(f[PK_DIRECT].p.role == PR_PRIMARY && f[PK_UDP_RELAY].p.role == PR_STANDBY, "roles with a direct path");
    CHECK(strcmp(pm_name(&m), "p2p") == 0 && strcmp(pm_label(&m), "P2P") == 0 && pm_code(&m) == NPF_PATH_DIRECT,
          "the direct path's name");

    /* the direct path in doubt: each datagram on both, the direct path first */
    pm_health(&m, &f[PK_DIRECT].p, PH_SUSPECT);
    CHECK(send1(&m) == (D | U), "dual send while in doubt");
    CHECK(m.primary == &f[PK_DIRECT].p && m.second == &f[PK_UDP_RELAY].p && f[PK_UDP_RELAY].p.role == PR_SECOND,
          "roles while in doubt");
    CHECK(strcmp(pm_name(&m), "p2p") == 0, "the name while in doubt");
    pm_health(&m, &f[PK_DIRECT].p, PH_UP);
    CHECK(send1(&m) == D && f[PK_UDP_RELAY].p.role == PR_STANDBY, "the doubt over");

    /* in doubt with no relay (released): the direct path alone still */
    pm_del(&m, &f[PK_UDP_RELAY].p);
    pm_health(&m, &f[PK_DIRECT].p, PH_SUSPECT);
    CHECK(send1(&m) == D && !m.second && f[PK_UDP_RELAY].p.role == PR_IDLE, "in doubt, no relay");
    pm_add(&m, &f[PK_UDP_RELAY].p);         /* a new allocation while in doubt: on both at once */
    CHECK(send1(&m) == (D | U), "a relay while in doubt");

    /* the WS relay is exclusive: whatever else is there, only it sends */
    pm_add(&m, &f[PK_WS_RELAY].p);
    CHECK(send1(&m) == W && !m.second, "the WS relay exclusive (%d)", send1(&m));
    CHECK(f[PK_WS_RELAY].p.role == PR_PRIMARY && f[PK_DIRECT].p.role == PR_IDLE && f[PK_UDP_RELAY].p.role == PR_IDLE,
          "roles on the WS relay");
    CHECK(strcmp(pm_name(&m), "ws relay") == 0 && strcmp(pm_label(&m), "Relayed") == 0
          && pm_code(&m) == NPF_PATH_WS_RELAY, "the WS relay's name");
    pm_health(&m, &f[PK_DIRECT].p, PH_UP);
    CHECK(send1(&m) == W, "still the WS relay alone");

    /* back to UDP: the WS relay goes */
    pm_del(&m, &f[PK_DIRECT].p);
    pm_del(&m, &f[PK_WS_RELAY].p);
    CHECK(send1(&m) == U && f[PK_WS_RELAY].p.role == PR_IDLE, "back on the UDP relay");
    pm_del(&m, &f[PK_WS_RELAY].p);          /* not in use: nothing changes */
    CHECK(send1(&m) == U, "a path removed twice");
    pm_del(&m, &f[PK_UDP_RELAY].p);
    CHECK(send1(&m) == 0 && !m.primary && strcmp(pm_name(&m), "none") == 0, "every path gone");

    /* a direct connection's fixed path: named direct whatever is in use */
    m.fixed = 1;
    CHECK(strcmp(pm_name(&m), "direct") == 0 && strcmp(pm_label(&m), "Direct") == 0 && pm_code(&m) == NPF_PATH_DIRECT,
          "a fixed path before it is up");
    pm_add(&m, &f[PK_DIRECT].p);
    CHECK(send1(&m) == D && strcmp(pm_name(&m), "direct") == 0, "a fixed path up");
    pm_health(&m, &f[PK_DIRECT].p, PH_SUSPECT);
    CHECK(send1(&m) == D, "a fixed path in doubt (no relay)");
    return fails;
}
