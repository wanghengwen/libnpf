/* Peers on npf.h alone: a direct peer at an IPv6 address ([::1], the IPv6
 * main socket of a direct instance), and peers removed from their own
 * callbacks (npf.h: from any callback): from the "forward" event of a new
 * forward (npf_forward_create says NPF_ENOENT), from the first forward's
 * "up" while its session starts (the other forwards tell nothing more),
 * from "peer_done". */
#define _DEFAULT_SOURCE
#include <signal.h>
#include <stdlib.h>

#include "api_test.h"

static npf_t *b;                        /* the instance whose callbacks remove */
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int remove_on;                   /* 1: a "forward" event, 2: a "forward" up, 3: "peer_done" */
static int removed_rc = -1, fwd_events, done_events, ups, downs, fwd_at_removal;
static char removed_json[256];

/* the peer an event names ({"peer": "TARGET", ...}), removed: npf_peer_remove's code */
static int remove_named(const char *json)
{
    const char *s = strstr(json, "\"peer\":\"");
    char target[300];
    size_t l;
    uint32_t id;
    if (!s)
        return -2;
    s += 8;
    l = strcspn(s, "\"");
    if (l >= sizeof target)
        return -2;
    memcpy(target, s, l);
    target[l] = 0;
    if (npf_peer_find(b, target, &id) != NPF_OK)
        return -3;
    return npf_peer_remove(b, id);
}

static void on_event(void *user, const char *name, const char *json)
{
    int fwd = strcmp(name, "forward") == 0, done = strcmp(name, "peer_done") == 0, rm;
    (void)user;
    if (!fwd && !done)
        return;
    pthread_mutex_lock(&mu);
    fwd_events += fwd;
    done_events += done;
    rm = (remove_on == 1 && fwd) || (remove_on == 2 && fwd && strstr(json, "\"up\":true")) || (remove_on == 3 && done);
    if (rm) {
        remove_on = 0;
        fwd_at_removal = fwd_events;
    }
    pthread_mutex_unlock(&mu);
    if (rm) {                           /* (on the instance's thread: npf_peer_remove runs here) */
        int r = remove_named(json);
        pthread_mutex_lock(&mu);
        removed_rc = r;
        snprintf(removed_json, sizeof removed_json, "%s", json);
        pthread_mutex_unlock(&mu);
    }
}

static void on_session(void *user, uint32_t session, int up, const char *info)
{
    (void)user, (void)session, (void)info;
    pthread_mutex_lock(&mu);
    ups += up;
    downs += !up;
    pthread_mutex_unlock(&mu);
}

static int get(int *v)
{
    int r;
    pthread_mutex_lock(&mu);
    r = *v;
    pthread_mutex_unlock(&mu);
    return r;
}

static void set_remove(int how)
{
    pthread_mutex_lock(&mu);
    remove_on = how;
    removed_rc = -1;
    removed_json[0] = 0;
    pthread_mutex_unlock(&mu);
}

static npf_t *make(const char *dir, const char *ov, int heard)
{
    npf_options o;
    npf_callbacks cb;
    npf_t *n = NULL;
    char err[300];
    npf_options_init(&o);
    o.conf_dir = dir;
    o.data_dir = dir;
    o.overrides = ov;
    o.role = NPF_ROLE_DIRECT;
    o.log_level = NPF_LEVEL_WARN;
    npf_callbacks_init(&cb);
    if (heard) {
        cb.event = on_event;
        cb.session = on_session;
    }
    o.cb = &cb;
    if (npf_create(&o, &n, err, sizeof err) != NPF_OK)
        return NULL;
    return n;
}

static int peer_count(void)
{
    size_t count = 99;
    uint32_t ids[8];
    return npf_peer_list(b, ids, 8, &count) == NPF_OK ? (int)count : -1;
}

static int fwd_count(void)
{
    size_t count = 99;
    uint32_t ids[8];
    return npf_forward_list(b, 0, ids, 8, &count) == NPF_OK ? (int)count : -1;
}

int main(void)
{
    char da[] = "/tmp/npf-peers-a-XXXXXX", db[] = "/tmp/npf-peers-b-XXXXXX", ov[300], err[300];
    static const uint8_t key[32] = {7, 7, 7};
    const char *keyb64 = "BwcHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char *host = "::1";
    npf_t *a = NULL;
    npf_peer_opt po;
    npf_peer_info pi;
    npf_forward_opt fo;
    uint32_t peer = 0, fwd = 0;
    int i, port = 0;
    alarm(120);
    signal(SIGPIPE, SIG_IGN);
    if (!mkdtemp(da) || !mkdtemp(db))
        return 2;

    /* A: a direct listener on [::1] (127.0.0.1 where the host has no IPv6) */
    for (i = 0; i < 40 && !a; i++) {
        port = 27880 + (int)((getpid() + i) % 40);
        snprintf(ov, sizeof ov, "udp_port = 0\ndirect = [::1]:%d\ndirect_psk = %s\n", port, keyb64);
        a = make(da, ov, 0);
    }
    if (!a) {
        printf("note: no IPv6 loopback: the IPv6 case on 127.0.0.1\n");
        host = "127.0.0.1";
        for (i = 0; i < 40 && !a; i++) {
            port = 27880 + (int)((getpid() + i) % 40);
            snprintf(ov, sizeof ov, "udp_port = 0\ndirect = 127.0.0.1:%d\ndirect_psk = %s\n", port, keyb64);
            a = make(da, ov, 0);
        }
    }
    check(a != NULL && npf_start(a) == NPF_OK, "A listening");
    b = make(db, "udp_port = 0\n", 1);
    check(b != NULL, "B made");
    if (!a || !b)
        return 1;
    npf_peer_opt_init(&po);
    po.target = NPF_TARGET_DIRECT;
    po.host = host;
    po.port = (uint16_t)port;
    po.psk = key;

    /* removed from the first forward's "up" as its session starts (made
     * before the start: the forwards start with the session): the other
     * forwards tell nothing more */
    set_remove(2);
    check(npf_peer_create(b, &po, &peer, err, sizeof err) == NPF_OK, "a peer at [::1] with three forwards");
    for (i = 0; i < 3; i++) {
        npf_forward_opt_init(&fo);
        fo.kind = NPF_FWD_LOCAL;
        fo.target.host = "127.0.0.1";
        fo.target.port = (uint16_t)(i + 1);
        check(npf_forward_create(b, peer, &fo, &fwd, err, sizeof err) == NPF_OK, "a local forward");
    }
    check(npf_start(b) == NPF_OK, "B started");
    WAIT_UNTIL(get(&removed_rc) != -1, 10000);
    check(get(&removed_rc) == NPF_OK && strstr(removed_json, "\"up\":true"), "removed in its first forward's up");
    sleep_ms(300);
    check(get(&fwd_events) == get(&fwd_at_removal) && peer_count() == 0 && fwd_count() == 0, "nothing more from it; it and its forwards gone");
    WAIT_UNTIL(get(&downs) >= 1, 5000);
    check(get(&ups) == 1 && get(&downs) == 1, "its session (over IPv6) up, then down");

    /* a direct peer at an IPv6 address: its session from B's IPv6 socket */
    check(npf_peer_create(b, &po, &peer, err, sizeof err) == NPF_OK && peer, "the peer again");
    WAIT_UNTIL(get(&ups) >= 2, 10000);
    check(get(&ups) == 2 && npf_peer_get(b, peer, &pi) == NPF_OK && pi.state == NPF_PEER_CONNECTED
          && strcmp(pi.host, host) == 0 && pi.port == port && pi.session, "its session up, the address as given");

    /* removed from the "forward" event of a forward being made */
    set_remove(1);
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_SOCKS;
    i = npf_forward_create(b, peer, &fo, &fwd, err, sizeof err);
    check(i == NPF_ENOENT && get(&removed_rc) == NPF_OK, "removed in its new forward's event: create says NPF_ENOENT");
    check(peer_count() == 0 && fwd_count() == 0 && npf_peer_get(b, peer, &pi) == NPF_ENOENT, "the peer and forward gone");
    WAIT_UNTIL(get(&downs) >= 2, 5000);
    check(get(&downs) == 2, "its session down");

    /* removed from "peer_done": a one-off peer whose session A ends */
    set_remove(3);
    po.connect = NPF_CONNECT_ONCE;
    check(npf_peer_create(b, &po, &peer, err, sizeof err) == NPF_OK, "a one-off peer");
    WAIT_UNTIL(get(&ups) >= 3, 10000);
    check(get(&ups) == 3, "its session up");
    npf_destroy(a);                     /* the listener's close ends B's session */
    WAIT_UNTIL(get(&removed_rc) != -1, 10000);
    check(get(&removed_rc) == NPF_OK && get(&done_events) == 1 && peer_count() == 0, "removed in its peer_done");
    sleep_ms(100);                      /* the next turn frees it */
    check(get(&done_events) == 1 && peer_count() == 0, "nothing more from it");

    npf_destroy(b);
    rm_dir(da);
    rm_dir(db);
    printf("%s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}
