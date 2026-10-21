/* npf.h's objects on npf.h alone (docs/design/api-draft.md): two direct
 * instances on loopback. A publishes an echo service; B makes a peer to A
 * with forwards and hears typed events. Resources, peers, forwards, their
 * rules and limits, the events' order and ctx, lists with the caller's
 * element size, a change that cannot be saved and npf_save, a restart that
 * brings the saved peer back, NPF_OPT_NO_SAVED_OBJECTS, npf_setup. */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "npf.h"

static int fails;
static void check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    fails += !ok;
}

/* ---- an echo service ---- */

static int echo_fd;
static void *echo_main(void *arg)
{
    (void)arg;
    for (;;) {
        char b[4096];
        ssize_t r;
        int c = accept(echo_fd, NULL, NULL);
        if (c < 0)
            return NULL;
        while ((r = read(c, b, sizeof b)) > 0)
            if (write(c, b, (size_t)r) != r)
                break;
        close(c);
    }
}

static int echo_start(void)
{
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    pthread_t t;
    echo_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(echo_fd, (struct sockaddr *)&a, sizeof a) < 0 || listen(echo_fd, 8) < 0)
        return -1;
    getsockname(echo_fd, (struct sockaddr *)&a, &l);
    pthread_create(&t, NULL, echo_main, NULL);
    pthread_detach(t);
    return ntohs(a.sin_port);
}

/* through a forward listening on port: what is sent comes back */
static int echoes(int port)
{
    struct sockaddr_in a;
    char b[16] = "";
    struct timeval tv = {5, 0};
    int fd = socket(AF_INET, SOCK_STREAM, 0), ok;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ok = connect(fd, (struct sockaddr *)&a, sizeof a) == 0 && write(fd, "ping", 4) == 4 && read(fd, b, 4) == 4
         && memcmp(b, "ping", 4) == 0;
    close(fd);
    return ok;
}

/* a SOCKS5 CONNECT through port to 127.0.0.1:tport: the reply code (0 ok), -1 none */
static int socks_connect(int port, int tport)
{
    struct sockaddr_in a;
    unsigned char b[16];
    struct timeval tv = {5, 0};
    int fd = socket(AF_INET, SOCK_STREAM, 0), rep = -1;
    unsigned char req[10] = {5, 1, 0, 1, 127, 0, 0, 1, 0, 0};
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    req[8] = (unsigned char)(tport >> 8);
    req[9] = (unsigned char)tport;
    if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0 && write(fd, "\5\1\0", 3) == 3 && read(fd, b, 2) == 2
        && write(fd, req, 10) == 10 && read(fd, b, 10) >= 2)
        rep = b[1];
    close(fd);
    return rep;
}

/* ---- the events B hears ---- */

#define MAXEV 512
typedef struct evrec {
    int      type, state, reason;
    uint32_t peer, forward, session;
    void    *ctx;
} evrec;

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static evrec evs[MAXEV];
static int nev, after_stopped;

static void on_notify(void *user, const npf_event *ev)
{
    (void)user;
    pthread_mutex_lock(&mu);
    if (nev && evs[nev - 1].type == NPF_EV_STOPPED)
        after_stopped++;
    if (nev < MAXEV) {
        evs[nev].type = ev->type;
        evs[nev].state = ev->state;
        evs[nev].reason = ev->reason;
        evs[nev].peer = ev->peer;
        evs[nev].forward = ev->forward;
        evs[nev].session = ev->session;
        evs[nev].ctx = ev->ctx;
        nev++;
    }
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
}

/* the index of the first event from from on of type (and state >= 0), waiting up to ms; -1 none */
static int wait_ev(int from, int type, int state, int ms)
{
    struct timespec ts;
    int i;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    pthread_mutex_lock(&mu);
    for (;;) {
        for (i = from; i < nev; i++)
            if (evs[i].type == type && (state < 0 || evs[i].state == state)) {
                pthread_mutex_unlock(&mu);
                return i;
            }
        if (pthread_cond_timedwait(&cv, &mu, &ts) != 0)
            break;
    }
    pthread_mutex_unlock(&mu);
    return -1;
}

static int ev_count(void)
{
    int n;
    pthread_mutex_lock(&mu);
    n = nev;
    pthread_mutex_unlock(&mu);
    return n;
}

static npf_t *make(const char *dir, int role, const char *ov, int typed, int flags, char *err, size_t errcap)
{
    npf_options o;
    npf_callbacks cb;
    npf_t *n = NULL;
    npf_options_init(&o);
    o.conf_dir = dir;
    o.data_dir = dir;
    o.overrides = ov;
    o.role = role;
    o.log_level = NPF_LEVEL_WARN;
    o.flags = flags;
    npf_callbacks_init(&cb);
    if (typed)
        cb.notify = on_notify;
    o.cb = &cb;
    if (npf_create(&o, &n, err, errcap) != NPF_OK)
        return NULL;
    return n;
}

static int file_has(const char *dir, const char *what)
{
    char path[300], buf[16384];
    FILE *f;
    size_t l = 0;
    snprintf(path, sizeof path, "%s/local.json", dir);
    if ((f = fopen(path, "r"))) {
        l = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
    }
    buf[l] = 0;
    return strstr(buf, what) != NULL;
}

static void resources(npf_t *a, const char *da, int echo)
{
    npf_resource r;
    npf_resource_info info[40], *big;
    size_t count, elem;
    char err[300], name[16];
    int i, ok;
    npf_resource_init(&r);
    r.type = NPF_RES_TCP;
    r.name = "echo";
    r.service.host = "127.0.0.1";
    r.service.port = (uint16_t)echo;
    r.desc = "an echo";
    r.flags = NPF_PERSIST;
    check(npf_resource_put(a, &r, err, sizeof err) == NPF_OK && file_has(da, "\"echo\""), "resource put: saved");
    npf_resource_init(&r);
    r.type = NPF_RES_REVERSE;
    r.name = "back";
    r.rule = "lan:*";
    check(npf_resource_put(a, &r, err, sizeof err) == NPF_OK && !file_has(da, "\"back\""),
          "a resource without NPF_PERSIST: in effect, not in local.json");
    r.rule = "lan:70000";
    check(npf_resource_put(a, &r, err, sizeof err) == NPF_EINVAL, "a bad rule: NPF_EINVAL");
    npf_resource_init(&r);
    r.type = NPF_RES_TCP;
    r.name = "web";
    r.svc = "http";
    r.service.host = "::1";
    r.service.port = 8080;
    r.path = "/admin";
    check(npf_resource_put(a, &r, err, sizeof err) == NPF_OK, "a web page on an IPv6 address");
    for (i = 0, ok = 1; i < NPF_RESOURCES_MAX - 3; i++) {
        snprintf(name, sizeof name, "r%d", i);
        r.name = name;
        r.svc = NULL;
        r.path = NULL;
        ok &= npf_resource_put(a, &r, err, sizeof err) == NPF_OK;
    }
    r.name = "one-too-many";
    check(ok && npf_resource_put(a, &r, err, sizeof err) == NPF_EBUSY, "the resources' limit: NPF_EBUSY");
    check(npf_resource_list(a, 0, info, 40, &count) == NPF_OK && count == NPF_RESOURCES_MAX
          && strcmp(info[0].name, "echo") == 0 && info[0].port == echo && (info[0].flags & NPF_PERSIST)
          && info[0].saved && strcmp(info[1].rule, "lan:*") == 0 && !(info[1].flags & NPF_PERSIST)
          && strcmp(info[2].host, "::1") == 0 && strcmp(info[2].path, "/admin") == 0,
          "resource list: parts back");
    check(npf_resource_list(a, 0, info, 3, &count) == NPF_ETOOBIG && count == NPF_RESOURCES_MAX,
          "a short list: NPF_ETOOBIG, the count all");
    /* a newer application's larger elements: written at its stride, tails zeroed, size kept */
    elem = sizeof(npf_resource_info) + 24;
    big = malloc(elem * 3 + 16);
    memset(big, 0xaa, elem * 3 + 16);
    ok = npf_resource_list_size(a, 0, big, elem, 2, &count) == NPF_ETOOBIG;
    {
        unsigned char *b = (unsigned char *)big;
        size_t k;
        npf_resource_info e1;
        memcpy(&e1, b + elem, sizeof e1);
        ok = ok && e1.size == elem && strcmp(e1.name, "back") == 0;
        for (k = sizeof(npf_resource_info); k < elem; k++)
            ok = ok && b[k] == 0 && b[elem + k] == 0;
        for (k = 2 * elem; k < elem * 3 + 16; k++)
            ok = ok && b[k] == 0xaa;
    }
    check(ok, "a list of larger elements: the caller's stride, tails zeroed, nothing past the array");
    check(npf_resource_list_size(a, 0, big, sizeof(npf_resource_info) - 8, 2, &count) == NPF_EINVAL,
          "elements smaller than the first version: NPF_EINVAL");
    free(big);
    for (i = 0; i < NPF_RESOURCES_MAX - 3; i++) {
        snprintf(name, sizeof name, "r%d", i);
        npf_resource_remove(a, name);
    }
    check(npf_resource_remove(a, "web") == NPF_OK && npf_resource_remove(a, "web") == NPF_ENOENT, "resource remove");
}

int main(void)
{
    char da[] = "/tmp/npf-obj-a-XXXXXX", db[] = "/tmp/npf-obj-b-XXXXXX", dc[] = "/tmp/npf-obj-c-XXXXXX";
    char ov[300], err[300];
    static const uint8_t key[32] = {1, 2, 3};
    const char *keyb64 = "AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int dport = 47930 + (int)(getpid() % 40), echo, i, j, k, ok;
    int ctx_peer, ctx_fwd, ctx_socks;
    npf_t *a, *b, *c;
    npf_peer_opt po;
    npf_peer_info pi;
    npf_forward_opt fo;
    npf_forward_info fi;
    npf_node_info ni;
    uint32_t peer = 0, fwd = 0, socks = 0, other = 0, ids[8];
    size_t count;
    alarm(120);
    if (!mkdtemp(da) || !mkdtemp(db) || !mkdtemp(dc) || (echo = echo_start()) < 0)
        return 2;

    /* A: a direct node with an echo service published */
    snprintf(ov, sizeof ov, "udp_port = 0\ndirect = 127.0.0.1:%d\ndirect_psk = %s\n", dport, keyb64);
    a = make(da, NPF_ROLE_DIRECT, ov, 0, 0, err, sizeof err);
    check(a != NULL, "A made");
    if (!a)
        return 1;
    resources(a, da, echo);
    check(npf_start(a) == NPF_OK, "A started");

    /* B: its peer to A, before the start (no events yet) */
    b = make(db, NPF_ROLE_DIRECT, "udp_port = 0\n", 1, 0, err, sizeof err);
    check(b != NULL, "B made (typed events)");
    if (!b)
        return 1;
    npf_peer_opt_init(&po);
    po.target = NPF_TARGET_DIRECT;
    po.host = "LocalHost";
    po.port = (uint16_t)dport;
    po.psk = key;
    po.connect = NPF_CONNECT_ONCE;
    po.flags = NPF_PERSIST;
    check(npf_peer_create(b, &po, &peer, err, sizeof err) == NPF_EINVAL && !peer, "ONCE with PERSIST: NPF_EINVAL");
    po.connect = NPF_CONNECT_ON_DEMAND;
    po.flags = 0;
    check(npf_peer_create(b, &po, &peer, err, sizeof err) == NPF_EINVAL, "ON_DEMAND without PERSIST: NPF_EINVAL");
    po.connect = NPF_CONNECT_KEEP;
    po.name = "aa";
    po.ctx = &ctx_peer;
    check(npf_peer_create(b, &po, &peer, err, sizeof err) == NPF_OK && peer, "peer create (a name, a ctx)");
    po.host = "localhost";
    po.name = NULL;
    check(npf_peer_create(b, &po, &other, err, sizeof err) == NPF_EEXIST && other == peer,
          "the same target in another spelling: NPF_EEXIST and its number");
    check(npf_peer_find(b, "aa", &other) == NPF_OK && other == peer && npf_peer_find(b, "LOCALHOST:0", &other) == NPF_ENOENT,
          "peer find by name");
    npf_peer_info_init(&pi);
    check(npf_peer_get(b, peer, &pi) == NPF_OK && pi.target == NPF_TARGET_DIRECT && strcmp(pi.host, "localhost") == 0
          && pi.port == dport && strcmp(pi.name, "aa") == 0 && pi.connect == NPF_CONNECT_KEEP && pi.flags == 0
          && pi.state == NPF_PEER_WAITING, "peer get: before the start");
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_LOCAL;
    fo.target.host = "127.0.0.1";
    fo.target.port = (uint16_t)echo;
    fo.ctx = &ctx_fwd;
    check(npf_forward_create(b, peer, &fo, &fwd, err, sizeof err) == NPF_OK && fwd, "a local forward, port 0");
    fo.flags = NPF_PERSIST;
    check(npf_forward_create(b, peer, &fo, &other, err, sizeof err) == NPF_EINVAL,
          "a saved forward on a temporary peer: NPF_EINVAL");
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_SOCKS;
    fo.ctx = &ctx_socks;
    check(npf_forward_create(b, peer, &fo, &socks, err, sizeof err) == NPF_OK, "a SOCKS forward, port 0");
    fo.proto = NPF_PROTO_UDP;
    check(npf_forward_create(b, peer, &fo, &other, err, sizeof err) == NPF_EINVAL, "UDP SOCKS: NPF_EINVAL");
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_LOCAL;
    check(npf_forward_create(b, peer, &fo, &other, err, sizeof err) == NPF_EINVAL, "no target: NPF_EINVAL");
    check(npf_peer_list(b, ids, 8, &count) == NPF_OK && count == 1 && ids[0] == peer
          && npf_forward_list(b, peer, ids, 8, &count) == NPF_OK && count == 2, "lists");
    check(ev_count() == 0, "no events before the start");

    /* the run: the session, the forwards up, events with the ctx */
    check(npf_start(b) == NPF_OK, "B started");
    i = wait_ev(0, NPF_EV_SESSION_UP, -1, 10000);
    check(i >= 0 && evs[i].peer == peer && evs[i].ctx == &ctx_peer && evs[i].session, "SESSION_UP with the peer's ctx");
    j = wait_ev(0, NPF_EV_PEER, NPF_PEER_CONNECTED, 5000);
    check(j >= 0 && evs[j].ctx == &ctx_peer, "PEER connected, its ctx");
    k = wait_ev(0, NPF_EV_FORWARD, NPF_FWD_UP, 5000);
    check(k >= 0 && evs[k].ctx == &ctx_fwd, "FORWARD up, its ctx");
    npf_forward_info_init(&fi);
    ok = npf_forward_get(b, fwd, &fi) == NPF_OK && fi.state == NPF_FWD_UP && fi.listen_port && fi.peer == peer
         && strcmp(fi.listen_host, "127.0.0.1") == 0 && fi.target_port == echo;
    check(ok, "forward get: up, the port the system picked");
    check(ok && echoes(fi.listen_port), "through it to A's echo service");
    {
        npf_session_info si;
        npf_session_info_init(&si);
        check(npf_session_list(b, ids, 8, &count) == NPF_OK && count == 1 && npf_session_get(b, ids[0], &si) == NPF_OK
              && si.peer == peer && si.outgoing && si.path == NPF_PATH_DIRECT, "session get");
    }
    /* SOCKS: a published target goes, another is refused, the listener stays up */
    npf_forward_info_init(&fi);
    npf_forward_get(b, socks, &fi);
    k = ev_count();
    check(socks_connect(fi.listen_port, echo) == 0, "SOCKS to the published service");
    check(socks_connect(fi.listen_port, 9) > 0, "SOCKS to a target not published: refused");
    i = wait_ev(k, NPF_EV_FORWARD_REFUSED, -1, 5000);
    npf_forward_info_init(&fi);
    check(i >= 0 && evs[i].forward == socks && evs[i].ctx == &ctx_socks && npf_forward_get(b, socks, &fi) == NPF_OK
          && fi.refused == 1 && fi.state == NPF_FWD_UP, "FORWARD_REFUSED; counted; the rule still up");
    check(socks_connect(fi.listen_port, echo) == 0, "and the published one still goes");

    /* names, flags, saving */
    check(npf_peer_set_names(b, peer, "bb", "a nick") == NPF_OK && npf_peer_get(b, peer, &pi) == NPF_OK
          && strcmp(pi.name, "bb") == 0 && strcmp(pi.nick, "a nick") == 0, "set names");
    check(npf_peer_set_flags(b, peer, NPF_PERSIST) == NPF_OK && file_has(db, "\"save\": true"),
          "set_flags: saved now");
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_LOCAL;
    fo.listen.port = 0;
    fo.target.host = "127.0.0.1";
    fo.target.port = (uint16_t)echo;
    fo.flags = NPF_PERSIST;
    fo.listen.host = "0.0.0.0";        /* every address (macOS has 127.0.0.1 alone on lo0) */
    check(npf_forward_create(b, peer, &fo, &other, err, sizeof err) == NPF_OK && file_has(db, "\"listen\": \"0.0.0.0\""),
          "a saved forward: in local.json as a record");
    check(file_has(db, "\"port\": 0"), "its port as asked: 0");
    chmod(db, 0500);
    if (access(db, W_OK) != 0) {
        npf_node_info_init(&ni);
        check(npf_peer_set_names(b, peer, "cc", NULL) == NPF_ESAVE && npf_node_get(b, &ni) == NPF_OK && ni.unsaved
              && npf_peer_get(b, peer, &pi) == NPF_OK && !pi.saved && strcmp(pi.name, "cc") == 0,
              "a change that cannot be saved: NPF_ESAVE, in effect, unsaved");
        check(npf_save(b) == NPF_ESAVE, "npf_save while it still cannot");
        chmod(db, 0700);
        check(npf_save(b) == NPF_OK && npf_node_get(b, &ni) == NPF_OK && !ni.unsaved && file_has(db, "\"cc\""),
              "npf_save: written");
    }
    chmod(db, 0700);

    /* removal: the session's end, each forward, the peer, in this order */
    k = ev_count();
    check(npf_peer_remove_id(b, peer) == NPF_OK && npf_peer_get(b, peer, &pi) == NPF_ENOENT, "peer removed");
    i = wait_ev(k, NPF_EV_SESSION_DOWN, -1, 5000);
    j = wait_ev(k, NPF_EV_PEER_GONE, -1, 5000);
    {
        int f1 = wait_ev(k, NPF_EV_FORWARD_GONE, -1, 2000), last = -1, x;
        pthread_mutex_lock(&mu);
        for (x = k; x < nev; x++)
            if (evs[x].type == NPF_EV_FORWARD_GONE)
                last = x;
        pthread_mutex_unlock(&mu);
        check(i >= 0 && f1 > i && last < j && j > 0 && evs[i].reason == NPF_END_LOCAL && evs[j].ctx == &ctx_peer,
              "SESSION_DOWN (local), FORWARD_GONE..., PEER_GONE with its ctx");
    }
    check(!file_has(db, "\"save\": true") && file_has(db, "\"cc\""), "its record: not saved any more, its name kept");

    /* a saved peer comes back at the next start, ctx set before it */
    npf_peer_opt_init(&po);
    po.target = NPF_TARGET_DIRECT;
    po.host = "127.0.0.1";
    po.port = (uint16_t)dport;
    po.psk = key;
    po.flags = NPF_PERSIST;
    po.connect = NPF_CONNECT_ON_DEMAND;
    check(npf_peer_create(b, &po, &peer, err, sizeof err) == NPF_OK, "a saved peer on demand");
    npf_forward_opt_init(&fo);
    fo.kind = NPF_FWD_REMOTE;
    fo.target.host = "127.0.0.1";
    fo.target.port = 1;
    check(npf_forward_create(b, peer, &fo, &other, err, sizeof err) == NPF_EINVAL, "a remote forward on demand: NPF_EINVAL");
    check(npf_peer_set_flags(b, peer, 0) == NPF_EINVAL, "an on-demand peer not saved any more: NPF_EINVAL");
    npf_stop(b);
    i = wait_ev(0, NPF_EV_STOPPED, -1, 5000);
    npf_destroy(b);
    check(i >= 0 && !after_stopped, "STOPPED the last event");
    pthread_mutex_lock(&mu);
    nev = 0;
    pthread_mutex_unlock(&mu);
    b = make(db, NPF_ROLE_DIRECT, "udp_port = 0\n", 1, 0, err, sizeof err);
    ok = b && npf_peer_list(b, ids, 8, &count) == NPF_OK && count == 1;
    npf_peer_info_init(&pi);
    ok = ok && npf_peer_get(b, ids[0], &pi) == NPF_OK && pi.flags == NPF_PERSIST && pi.connect == NPF_CONNECT_ON_DEMAND
         && pi.port == dport;
    check(ok, "after a restart: the saved peer back, on demand");
    if (b) {
        check(npf_peer_set_ctx(b, ids[0], &ctx_peer) == NPF_OK && npf_start(b) == NPF_OK
              && npf_peer_connect_now(b, ids[0]) == NPF_OK, "its ctx set before the start, woken");
        i = wait_ev(0, NPF_EV_SESSION_UP, -1, 10000);
        check(i >= 0 && evs[i].ctx == &ctx_peer, "its events carry that ctx");
        /* the way it connects, changed while it runs */
        check(npf_peer_set_connect(b, ids[0], NPF_CONNECT_ONCE, 0) == NPF_EINVAL, "a saved peer ONCE: NPF_EINVAL");
        check(npf_peer_set_connect(b, ids[0], NPF_CONNECT_KEEP, 0) == NPF_OK && !file_has(db, "on_demand")
              && npf_peer_get(b, ids[0], &pi) == NPF_OK && pi.connect == NPF_CONNECT_KEEP && pi.session,
              "set_connect KEEP: saved, its session goes on");
        j = ev_count();
        check(npf_peer_set_connect(b, ids[0], NPF_CONNECT_ON_DEMAND, 1500) == NPF_OK && file_has(db, "on_demand")
              && file_has(db, "\"idle_ms\": 1500"), "set_connect ON_DEMAND, 1.5 s: saved");
        i = wait_ev(j, NPF_EV_SESSION_DOWN, -1, 20000);    /* idle checks every 5 s: two of them */
        check(i >= 0 && evs[i].peer == ids[0], "on demand: the session ends once idle");
        npf_peer_opt_init(&po);
        po.target = NPF_TARGET_DIRECT;
        po.host = "127.0.0.2";
        po.port = (uint16_t)dport;
        po.psk = key;
        check(npf_peer_create(b, &po, &other, err, sizeof err) == NPF_OK
              && npf_peer_set_connect(b, other, NPF_CONNECT_ON_DEMAND, 0) == NPF_EINVAL
              && npf_peer_set_connect(b, other, NPF_CONNECT_ONCE, 0) == NPF_OK
              && npf_peer_get(b, other, &pi) == NPF_OK && pi.connect == NPF_CONNECT_ONCE,
              "a temporary peer: not on demand (NPF_EINVAL), ONCE");
        npf_destroy(b);
    }

    /* the application keeps its own objects */
    c = make(dc, NPF_ROLE_DIRECT, "udp_port = 0\n", 0, NPF_OPT_NO_SAVED_OBJECTS, err, sizeof err);
    check(c != NULL, "an instance with NPF_OPT_NO_SAVED_OBJECTS");
    if (c) {
        npf_resource r;
        npf_peer_opt_init(&po);
        po.target = NPF_TARGET_DIRECT;
        po.host = "127.0.0.1";
        po.port = (uint16_t)dport;
        po.psk = key;
        po.flags = NPF_PERSIST;
        check(npf_peer_create(c, &po, &peer, err, sizeof err) == NPF_EUNAVAIL && !peer, "a saved peer: NPF_EUNAVAIL");
        po.flags = 0;
        check(npf_peer_create(c, &po, &peer, err, sizeof err) == NPF_OK && npf_peer_set_flags(c, peer, NPF_PERSIST) == NPF_EUNAVAIL
              && npf_peer_set_names(c, peer, "here", NULL) == NPF_OK && !file_has(dc, "here"),
              "a temporary one: no saving, names only here");
        npf_resource_init(&r);
        r.type = NPF_RES_TCP;
        r.name = "x";
        r.service.host = "127.0.0.1";
        r.service.port = 1;
        r.flags = NPF_PERSIST;
        check(npf_resource_put(c, &r, err, sizeof err) == NPF_EUNAVAIL, "a saved resource: NPF_EUNAVAIL");
        npf_destroy(c);
    }

    /* npf_setup */
    {
        npf_setup su;
        npf_options o;
        npf_callbacks cb;
        char val[64];
        npf_setup_init(&su);
        su.direct_port = (uint16_t)(dport + 1);
        su.direct_psk = key;
        su.udp_port = 0;
        npf_options_init(&o);
        npf_callbacks_init(&cb);
        o.cb = &cb;
        o.setup = &su;
        o.role = NPF_ROLE_DIRECT;
        o.log_level = NPF_LEVEL_WARN;
        o.data_dir = dc;
        o.conf_dir = dc;
        check(npf_create(&o, &c, err, sizeof err) == NPF_EINVAL, "npf_setup with a conf_dir: NPF_EINVAL");
        o.conf_dir = NULL;
        o.overrides = "udp_port = 0\n";
        check(npf_create(&o, &c, err, sizeof err) == NPF_EINVAL && strstr(err, "udp_port"),
              "a field's key in the overrides: NPF_EINVAL naming it");
        o.overrides = "node = 127.0.0.1:1\n";
        check(npf_create(&o, &c, err, sizeof err) == NPF_EINVAL, "a node line: NPF_EINVAL");
        o.overrides = NULL;
        o.role = NPF_ROLE_NODE;
        check(npf_create(&o, &c, err, sizeof err) == NPF_EINVAL && strstr(err, "roots"), "a node without roots: NPF_EINVAL");
        o.role = NPF_ROLE_DIRECT;
        check(npf_create(&o, &c, err, sizeof err) == NPF_OK && npf_config_get(c, "direct", val, sizeof val) == NPF_OK
              && atoi(val) == dport + 1, "npf_setup: no configuration file, the fields as keys");
        check(npf_pairing_password_get(c, val, sizeof val) == NPF_ESTATE, "no number: pairing NPF_ESTATE");
        npf_destroy(c);
    }

    npf_destroy(a);
    {
        char cmd[400];
        snprintf(cmd, sizeof cmd, "rm -rf %s %s %s", da, db, dc);
        if (system(cmd) != 0)
            fails++;
    }
    printf("%s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}
