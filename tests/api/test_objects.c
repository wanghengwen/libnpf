/* npf.h's objects on npf.h alone (docs/design/api-draft.md): two direct
 * instances on loopback. A publishes an echo service; B makes a peer to A
 * with forwards and hears the events and sessions. Resources, peers,
 * forwards, their rules and limits, their ctx, lists with the caller's
 * element size, a change that cannot be saved and npf_save, a restart that
 * brings the saved peer back, NPF_OPT_NO_SAVED_OBJECTS, npf_setup. */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "api_test.h"

/* ---- an echo service ---- */

/* a connection of its own thread: one through a session that went (the
 * network changed) never ends here, its peer's FIN lost with the session
 * (a session that went without a word stays until it times out) */
static void *echo_conn(void *arg)
{
    int c = (int)(intptr_t)arg;
    char b[4096];
    ssize_t r;
    while ((r = read(c, b, sizeof b)) > 0)
        if (write(c, b, (size_t)r) != r)
            break;
    close(c);
    return NULL;
}

static int echo_fd;
static void *echo_main(void *arg)
{
    (void)arg;
    for (;;) {
        pthread_t t;
        int c = accept(echo_fd, NULL, NULL);
        if (c < 0)
            return NULL;
        if (pthread_create(&t, NULL, echo_conn, (void *)(intptr_t)c) == 0)
            pthread_detach(t);
        else
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

/* a connection to 127.0.0.1:port (reads time out after 5 s), -1 none */
static int lo_connect(int port)
{
    struct sockaddr_in a;
    struct timeval tv = {5, 0};
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* through a forward listening on port: what is sent comes back */
static int echoes(int port)
{
    char b[16] = "";
    int fd = lo_connect(port), ok = fd >= 0 && write(fd, "ping", 4) == 4 && read(fd, b, 4) == 4 && memcmp(b, "ping", 4) == 0;
    if (fd >= 0)
        close(fd);
    return ok;
}

/* a SOCKS5 CONNECT through port to 127.0.0.1:tport: the reply code (0 ok), -1 none */
static int socks_connect(int port, int tport)
{
    unsigned char b[16], req[10] = {5, 1, 0, 1, 127, 0, 0, 1, (unsigned char)(tport >> 8), (unsigned char)tport};
    int fd = lo_connect(port), rep = -1;
    if (fd >= 0 && write(fd, "\5\1\0", 3) == 3 && read(fd, b, 2) == 2 && write(fd, req, 10) == 10 && read(fd, b, 10) >= 2)
        rep = b[1];
    if (fd >= 0)
        close(fd);
    return rep;
}

/* ---- the events B hears (npf_callbacks.event, .session) ---- */

#define MAXEV 512
typedef struct evrec {
    char     name[24];                  /* the event's; "session" from the session callback */
    int      up;                        /* session: up 1, down 0; "forward": its "up" */
    uint32_t session;
    char     json[256];
} evrec;

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static evrec evs[MAXEV];
static int nev, after_stopped;

static void ev_add(const char *name, uint32_t session, int up, const char *json)
{
    pthread_mutex_lock(&mu);
    if (nev && strcmp(evs[nev - 1].name, "stopped") == 0)
        after_stopped++;
    if (nev < MAXEV) {
        snprintf(evs[nev].name, sizeof evs[nev].name, "%s", name);
        evs[nev].up = up;
        evs[nev].session = session;
        snprintf(evs[nev].json, sizeof evs[nev].json, "%s", json ? json : "");
        nev++;
    }
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&mu);
}

static void on_event(void *user, const char *name, const char *json)
{
    (void)user;
    ev_add(name, 0, strstr(json, "\"up\":true") != NULL, json);
}

static void on_session(void *user, uint32_t session, int up, const char *info)
{
    (void)user;
    ev_add("session", session, up, info);
}

/* the index of the first event from from on named name (with up when up >=
 * 0, its JSON with sub when not NULL), waiting up to ms; -1 none */
static int wait_ev(int from, const char *name, int up, const char *sub, int ms)
{
    struct timespec ts;
    int i;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    pthread_mutex_lock(&mu);
    for (;;) {
        for (i = from; i < nev; i++)
            if (strcmp(evs[i].name, name) == 0 && (up < 0 || evs[i].up == up) && (!sub || strstr(evs[i].json, sub))) {
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

/* the peer a session belongs to (npf_session_get), 0 none */
static uint32_t session_peer(npf_t *n, uint32_t session)
{
    npf_session_info si;
    return session && npf_session_get(n, session, &si) == NPF_OK ? si.peer : 0;
}

static npf_t *make(const char *dir, int role, const char *ov, int heard, int flags, char *err, size_t errcap)
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
    if (heard) {
        cb.event = on_event;
        cb.session = on_session;
    }
    o.cb = &cb;
    if (npf_create(&o, &n, err, errcap) != NPF_OK)
        return NULL;
    return n;
}

/* npf_peer_setopt with an int, a string */
static int seti(npf_t *n, uint32_t peer, int opt, int v)
{
    return npf_peer_setopt(n, peer, opt, &v, sizeof v);
}

static int sets(npf_t *n, uint32_t peer, int opt, const char *v)
{
    return npf_peer_setopt(n, peer, opt, v, 0);
}

/* local.json in dir has what */
static int file_has(const char *dir, const char *what)
{
    char buf[16384];
    return strstr(file_text(dir, "local.json", buf, sizeof buf), what) != NULL;
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
    /* udp: "*" or networks as a rule (no service host), listed back as a rule */
    npf_resource_init(&r);
    r.type = NPF_RES_UDP;
    r.name = "udp-all";
    r.rule = "*";
    check(npf_resource_put(a, &r, err, sizeof err) == NPF_OK && npf_resource_list(a, 0, info, 40, &count) == NPF_OK
          && count == 3 && info[2].type == NPF_RES_UDP && strcmp(info[2].rule, "*") == 0 && !info[2].host[0],
          "udp *: a rule");
    r.rule = "10.1.0.0/16:5000-5100";
    check(npf_resource_put(a, &r, err, sizeof err) == NPF_OK, "udp: a network with ports");
    r.rule = "lan";
    check(npf_resource_put(a, &r, err, sizeof err) == NPF_EINVAL, "udp lan: NPF_EINVAL");
    check(npf_resource_remove(a, "udp-all") == NPF_OK, "udp rule removed");
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
        ok = ok && strcmp(e1.name, "back") == 0;
        for (k = sizeof(npf_resource_info); k < elem; k++)
            ok = ok && b[k] == 0 && b[elem + k] == 0;
        for (k = 2 * elem; k < elem * 3 + 16; k++)
            ok = ok && b[k] == 0xaa;
    }
    check(ok, "a list of larger elements: the caller's stride, tails zeroed, nothing past the array");
    /* an older application's smaller elements (no path, no description): its stride, its size only */
    elem = offsetof(npf_resource_info, path);
    memset(big, 0xaa, elem * 2 + 16);
    ok = npf_resource_list_size(a, 0, big, elem, 2, &count) == NPF_ETOOBIG;
    {
        unsigned char *b = (unsigned char *)big;
        size_t k;
        npf_resource_info e1;
        memset(&e1, 0, sizeof e1);
        memcpy(&e1, b + elem, elem);
        ok = ok && strcmp(e1.name, "back") == 0;
        for (k = 2 * elem; k < elem * 2 + 16; k++)
            ok = ok && b[k] == 0xaa;
    }
    check(ok, "a list of smaller elements: the caller's stride, nothing past its size");
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
    /* below the ephemeral ports, apart from the API test's 277xx (ctest -j, other builds at once) */
    int dport = 0, echo, i, j, k, ok;
    int ctx_peer, ctx_fwd, ctx_socks;
    npf_t *a = NULL, *b, *c;
    npf_peer_opt po;
    npf_peer_info pi;
    npf_forward_opt fo;
    npf_forward_info fi;
    npf_node_info ni;
    uint32_t peer = 0, fwd = 0, socks = 0, other = 0, ids[8];
    size_t count;
    alarm(120);
    signal(SIGPIPE, SIG_IGN);               /* a connection the library ends while the echo service or a check writes */
    if (!mkdtemp(da) || !mkdtemp(db) || !mkdtemp(dc) || (echo = echo_start()) < 0)
        return 2;

    /* A: a direct node with an echo service published */
    for (i = 0; i < 40 && !a; i++) {        /* the next port when another run (another tree's) has it */
        dport = 27930 + (int)((getpid() + i) % 40);
        snprintf(ov, sizeof ov, "udp_port = 0\ndirect = 127.0.0.1:%d\ndirect_psk = %s\n", dport, keyb64);
        a = make(da, NPF_ROLE_DIRECT, ov, 0, 0, err, sizeof err);
    }
    check(a != NULL, "A made");
    if (!a)
        return 1;
    resources(a, da, echo);
    check(npf_start(a) == NPF_OK, "A started");

    /* B: its peer to A, before the start (no events yet) */
    b = make(db, NPF_ROLE_DIRECT, "udp_port = 0\n", 1, 0, err, sizeof err);
    check(b != NULL, "B made (its events heard)");
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
    check(wait_ev(0, "session", -1, NULL, 0) < 0 && wait_ev(0, "forward", 1, NULL, 0) < 0,
          "before the start: no session, no forward up");

    /* the run: the session, the forwards up, the peer's ctx */
    check(npf_start(b) == NPF_OK, "B started");
    i = wait_ev(0, "session", 1, NULL, 10000);
    check(i >= 0 && evs[i].session && session_peer(b, evs[i].session) == peer, "session up: the peer's");
    WAIT_UNTIL(npf_peer_get(b, peer, &pi) == NPF_OK && pi.state == NPF_PEER_CONNECTED, 5000);
    check(npf_peer_get(b, peer, &pi) == NPF_OK && pi.state == NPF_PEER_CONNECTED && pi.ctx == &ctx_peer
          && pi.session == evs[i].session, "peer connected, its ctx and session");
    k = wait_ev(0, "forward", 1, "\"-L ", 5000);
    check(k >= 0, "forward event: the local forward up");
    ok = npf_forward_get(b, fwd, &fi) == NPF_OK && fi.state == NPF_FWD_UP && fi.listen_port && fi.peer == peer
         && strcmp(fi.listen_host, "127.0.0.1") == 0 && fi.target_port == echo && fi.ctx == &ctx_fwd;
    check(ok, "forward get: up, the port the system picked, its ctx");
    {
        int other_ctx = 0;
        npf_forward_info f2;
        check(npf_forward_setopt(b, fwd, NPF_FWD_OPT_CTX, &other_ctx, 0) == NPF_OK && npf_forward_get(b, fwd, &f2) == NPF_OK
              && f2.ctx == &other_ctx && npf_forward_setopt(b, fwd, NPF_FWD_OPT_CTX, &ctx_fwd, sizeof(void *)) == NPF_EINVAL
              && npf_forward_setopt(b, fwd, NPF_FWD_OPT_CTX, &ctx_fwd, 0) == NPF_OK, "forward setopt CTX; a len: NPF_EINVAL");
    }
    check(ok && echoes(fi.listen_port), "through it to A's echo service");
    {
        npf_session_info si;
        check(npf_session_list(b, ids, 8, &count) == NPF_OK && count == 1 && npf_session_get(b, ids[0], &si) == NPF_OK
              && si.peer == peer && si.outgoing && si.path == NPF_PATH_DIRECT, "session get");
    }
    /* SOCKS: a published target goes, another is refused, the listener stays up */
    npf_forward_get(b, socks, &fi);
    k = ev_count();
    check(socks_connect(fi.listen_port, echo) == 0, "SOCKS to the published service");
    check(socks_connect(fi.listen_port, 9) > 0, "SOCKS to a target not published: refused");
    WAIT_UNTIL(npf_forward_get(b, socks, &fi) == NPF_OK && fi.refused >= 1, 5000);
    check(npf_forward_get(b, socks, &fi) == NPF_OK && fi.refused == 1
          && fi.state == NPF_FWD_UP && fi.ctx == &ctx_socks && strstr(fi.refused_why, "not published"),
          "a refusal counted, its target; the rule still up");
    check(socks_connect(fi.listen_port, echo) == 0, "and the published one still goes");

    /* the network changed: npf_network_changed, then the command netcheck
     * (npf_host's): the sockets open again, the session ends with the old
     * one and comes back, the forward with it */
    for (k = 0; k < 2; k++) {
        const char *nc[] = {"netcheck"};
        int from = ev_count();
        check(k ? cmd(b, 1, nc) == 0 : npf_network_changed(b) == NPF_OK, k ? "netcheck" : "npf_network_changed");
        i = wait_ev(from, "session", 0, NULL, 5000);
        j = i >= 0 ? wait_ev(i, "session", 1, NULL, 10000) : -1;
        check(i >= 0 && j > i && session_peer(b, evs[j].session) == peer, "the network changed: the session again");
        check(j > i && npf_forward_get(b, fwd, &fi) == NPF_OK && fi.state == NPF_FWD_UP && echoes(fi.listen_port),
              "the network changed: the forward through the new session");
    }

    /* names, flags, saving */
    check(sets(b, peer, NPF_PEER_OPT_NAME, "bb") == NPF_OK && sets(b, peer, NPF_PEER_OPT_NICK, "a nick") == NPF_OK
          && npf_peer_get(b, peer, &pi) == NPF_OK && strcmp(pi.name, "bb") == 0 && strcmp(pi.nick, "a nick") == 0
          && pi.ctx == &ctx_peer, "setopt NAME, NICK; the ctx in the info");
    {
        int v = 1;
        char nick[NPF_NICK_MAX + 2];
        memset(nick, 'x', sizeof nick - 1);
        nick[sizeof nick - 1] = 0;
        check(npf_peer_setopt(b, peer, NPF_PEER_OPT_PERSIST, &v, 1) == NPF_EINVAL
              && npf_peer_setopt(b, peer, NPF_PEER_OPT_NAME, "dd", 3) == NPF_EINVAL
              && npf_peer_setopt(b, peer, 99, &v, sizeof v) == NPF_EINVAL && seti(b, peer, NPF_PEER_OPT_PERSIST, 2) == NPF_EINVAL
              && sets(b, peer, NPF_PEER_OPT_NICK, nick) == NPF_EINVAL && seti(b, peer, NPF_PEER_OPT_IDLE_MS, -1) == NPF_EINVAL
              && npf_peer_get(b, peer, &pi) == NPF_OK && strcmp(pi.name, "bb") == 0 && strcmp(pi.nick, "a nick") == 0
              && !(pi.flags & NPF_PERSIST), "setopt: a wrong len, option, value or length: NPF_EINVAL, unchanged");
    }
    check(seti(b, peer, NPF_PEER_OPT_PERSIST, 1) == NPF_OK && file_has(db, "\"save\": true") && file_has(db, "\"psk\""),
          "setopt PERSIST 1: saved now, a direct peer with its key");
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
        check(sets(b, peer, NPF_PEER_OPT_NAME, "cc") == NPF_ESAVE && npf_node_get(b, &ni) == NPF_OK && ni.unsaved
              && npf_peer_get(b, peer, &pi) == NPF_OK && !pi.saved && strcmp(pi.name, "cc") == 0,
              "a change that cannot be saved: NPF_ESAVE, in effect, unsaved");
        check(npf_save(b) == NPF_ESAVE, "npf_save while it still cannot");
        chmod(db, 0700);
        check(npf_save(b) == NPF_OK && npf_node_get(b, &ni) == NPF_OK && !ni.unsaved && file_has(db, "\"cc\""),
              "npf_save: written");
    }
    chmod(db, 0700);

    /* removal: the session ends, the forwards go with the peer */
    k = ev_count();
    check(npf_peer_remove(b, peer) == NPF_OK && npf_peer_get(b, peer, &pi) == NPF_ENOENT
          && npf_forward_get(b, fwd, &fi) == NPF_ENOENT && npf_forward_list(b, 0, ids, 8, &count) == NPF_OK && !count,
          "peer removed, its forwards with it");
    i = wait_ev(k, "session", 0, NULL, 5000);
    check(i >= 0 && strstr(evs[i].json, "\"why\""), "its session down");
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
    check(seti(b, peer, NPF_PEER_OPT_PERSIST, 0) == NPF_EINVAL, "an on-demand peer not saved any more: NPF_EINVAL");
    npf_stop(b);
    i = wait_ev(0, "stopped", -1, NULL, 5000);
    npf_destroy(b);
    check(i >= 0 && !after_stopped, "stopped: the last event");
    pthread_mutex_lock(&mu);
    nev = 0;
    pthread_mutex_unlock(&mu);
    b = make(db, NPF_ROLE_DIRECT, "udp_port = 0\n", 1, 0, err, sizeof err);
    ok = b && npf_peer_list(b, ids, 8, &count) == NPF_OK && count == 1;
    ok = ok && npf_peer_get(b, ids[0], &pi) == NPF_OK && pi.flags == NPF_PERSIST && pi.connect == NPF_CONNECT_ON_DEMAND
         && pi.port == dport;
    check(ok, "after a restart: the saved peer back, on demand");
    if (b) {
        check(npf_peer_setopt(b, ids[0], NPF_PEER_OPT_CTX, &ctx_peer, 0) == NPF_OK && npf_start(b) == NPF_OK
              && npf_peer_connect_now(b, ids[0]) == NPF_OK, "its ctx set before the start, woken");
        i = wait_ev(0, "session", 1, NULL, 10000);
        check(i >= 0 && session_peer(b, evs[i].session) == ids[0] && npf_peer_get(b, ids[0], &pi) == NPF_OK
              && pi.ctx == &ctx_peer, "its session up; its ctx kept");
        k = i;
        /* the way it connects, changed while it runs */
        check(seti(b, ids[0], NPF_PEER_OPT_CONNECT, NPF_CONNECT_ONCE) == NPF_EINVAL, "a saved peer ONCE: NPF_EINVAL");
        check(seti(b, ids[0], NPF_PEER_OPT_CONNECT, NPF_CONNECT_KEEP) == NPF_OK && !file_has(db, "on_demand")
              && npf_peer_get(b, ids[0], &pi) == NPF_OK && pi.connect == NPF_CONNECT_KEEP && pi.session,
              "setopt CONNECT KEEP: saved, its session goes on");
        j = ev_count();
        check(seti(b, ids[0], NPF_PEER_OPT_IDLE_MS, 1500) == NPF_OK && file_has(db, "\"idle_ms\": 1500")
              && !file_has(db, "on_demand"), "setopt IDLE_MS while kept: saved for later, still kept");
        check(seti(b, ids[0], NPF_PEER_OPT_CONNECT, NPF_CONNECT_ON_DEMAND) == NPF_OK && file_has(db, "on_demand")
              && file_has(db, "\"idle_ms\": 1500"), "setopt CONNECT ON_DEMAND (1.5 s): saved");
        i = wait_ev(j, "session", 0, NULL, 20000);    /* idle checks every 5 s: two of them */
        check(i >= 0 && evs[i].session == evs[k].session, "on demand: the session ends once idle");
        npf_peer_opt_init(&po);
        po.target = NPF_TARGET_DIRECT;
        po.host = "127.0.0.2";
        po.port = (uint16_t)dport;
        po.psk = key;
        check(npf_peer_create(b, &po, &other, err, sizeof err) == NPF_OK
              && seti(b, other, NPF_PEER_OPT_CONNECT, NPF_CONNECT_ON_DEMAND) == NPF_EINVAL
              && seti(b, other, NPF_PEER_OPT_CONNECT, NPF_CONNECT_ONCE) == NPF_OK
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
        check(npf_peer_create(c, &po, &peer, err, sizeof err) == NPF_OK && seti(c, peer, NPF_PEER_OPT_PERSIST, 1) == NPF_EUNAVAIL
              && sets(c, peer, NPF_PEER_OPT_NAME, "here") == NPF_OK && !file_has(dc, "here"),
              "a temporary one: no saving, names only here");
        check(sets(c, peer, NPF_PEER_OPT_NICK, "nick here") == NPF_OK && npf_peer_get(c, peer, &pi) == NPF_OK
              && strcmp(pi.nick, "nick here") == 0 && !file_has(dc, "nick here"),
              "its nick: kept for this run (npf_peer_get), not saved");
        npf_resource_init(&r);
        r.type = NPF_RES_TCP;
        r.name = "x";
        r.service.host = "127.0.0.1";
        r.service.port = 1;
        r.flags = NPF_PERSIST;
        check(npf_resource_put(c, &r, err, sizeof err) == NPF_EUNAVAIL, "a saved resource: NPF_EUNAVAIL");
        npf_destroy(c);
    }

    /* the application keeps its settings: npf_command's set saves nothing either */
    c = make(dc, NPF_ROLE_DIRECT, "udp_port = 0\n", 0, NPF_OPT_NO_SAVED_SETTINGS, err, sizeof err);
    check(c != NULL, "an instance with NPF_OPT_NO_SAVED_SETTINGS");
    if (c) {
        const char *set1[] = {"set", "log_level", "debug"}, *set2[] = {"set", "log_level", "debug", "--no-save"};
        check(npf_config_set(c, "log_level", "debug", 1, err, sizeof err) == NPF_EUNAVAIL && cmd(c, 3, set1) == 1
              && strstr(cmd_text, "not saved here") && cmd(c, 4, set2) == 0 && !file_has(dc, "debug"),
              "set with saving: refused (npf_config_set and the command), --no-save in effect");
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
        {
            static char model[1100];
            memset(model, 'm', sizeof model - 1);
            su.model = model;           /* longer than a value holds */
            check(npf_create(&o, &c, err, sizeof err) != NPF_OK && strstr(err, "model"),
                  "a field too long for its key: refused, naming it");
            su.model = NULL;
        }
        if (npf_create(&o, &c, err, sizeof err) != NPF_OK) {
            printf("     (%s)\n", err);
            c = NULL;
        }
        check(c && npf_config_get(c, "direct", val, sizeof val) == NPF_OK && atoi(val) == dport + 1,
              "npf_setup: no configuration file, the fields as keys");
        check(c && npf_pairing_password_get(c, val, sizeof val) == NPF_ESTATE, "no number: pairing NPF_ESTATE");
        npf_destroy(c);
    }

    npf_destroy(a);
    rm_dir(da);
    rm_dir(db);
    rm_dir(dc);
    printf("%s\n", fails ? "FAILED" : "ok");
    return fails != 0;
}
