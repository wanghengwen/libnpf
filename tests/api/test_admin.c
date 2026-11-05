/* The admins' requests on a node (security.md D25, src/api/admin.c), the
 * authorization matrix on an instance with a number, not started: an
 * admin's IK and PAKE sessions may (an entry of before the roles is an
 * admin), a member gets its role only and is refused the rest, GRANT and
 * DIRECT sessions are refused even with an admin's key; remote_admin
 * members refuses resources, off everything; paging (100 a page), the
 * share codes listed without their secrets; an admin unpairs members only,
 * not an admin (itself or another); unknown keys, names and locators are
 * not_found, a resource of npf.conf cannot be replaced or removed, a bad
 * resource says why; a share code needs the platform (offline), which says
 * whether it needs an owner (no_owner: a model device's does not), its uses and ttl bounded, and the code made later goes only
 * to the session of the admin that asked; there are no role changes; each
 * request is logged with the caller's fingerprint, at most 30 lines a minute.
 * The node's peers (remote-peers.md): listed with their forwards and who
 * added them; a device paired before is added without a share code, one
 * already a peer is existing, any other needs a share code (a password is
 * refused), at most 8 added remotely; a -L only to a service the peer
 * published, on loopback or every address, ports from 1024, at most 8 a
 * peer, the adder kept in local.json; remote admins remove only what remote
 * admins added; members, GRANT and remote_admin members are refused. */
#define _DEFAULT_SOURCE                     /* mkdtemp */
#include <stdlib.h>

#include "api_test.h"
#include "api_internal.h"
#include "call_internal.h"
#include "msgs.h"

static void key_of(int i, uint8_t k[32])
{
    memset(k, 0, 32);
    k[0] = (uint8_t)(i + 1);
    k[31] = 0x40;
}

/* the request {type, data} from a session (auth, the key of entry i): its
 * error ("" done) and the reply's data in out */
static const char *req(npf_t *n, int auth, int who, const char *type, const char *data, char *out, size_t cap)
{
    static npf_jtok tok[256];
    static char err[32];
    char msg[512];
    uint8_t pub[32];
    npf_json j;
    npf_env e;
    npf_out o = {0};
    const char *r;
    key_of(who, pub);
    snprintf(msg, sizeof msg, "{\"v\":1,\"type\":\"%s\",\"id\":\"r1\",\"data\":%s}", type, data);
    if (npf_json_parse(&j, msg, strlen(msg), tok, 256) < 0 || node_env(&j, &e) < 0)
        return "unparsed";
    r = npf_admin_do(n, NULL, auth, pub, &e, &o);
    npf_out_jend(&o);
    snprintf(out, cap, "%s", o.p ? o.p : "");
    npf_out_free(&o);
    snprintf(err, sizeof err, "%s", r ? r : "");
    return err;
}

static int ok(const char *e) { return e[0] == 0; }
static int is(const char *e, const char *want) { return strcmp(e, want) == 0; }

static void keyjson(int i, char *out)
{
    uint8_t k[32];
    char b[NPF_B64_LEN(32)];
    key_of(i, k);
    npf_b64url_encode(k, 32, b);
    sprintf(out, "{\"key\":\"%s\"}", b);
}

/* the k-th valid device number from 100000000 on (its check digit) */
static uint64_t number(int k)
{
    uint64_t v;
    char s[16];
    for (v = 100000000; ; v++) {
        snprintf(s, sizeof s, "%llu", (unsigned long long)v);
        if (npf_number_parse(s) && v != 123456789 && k-- == 0)
            return v;
    }
}

/* the id after "id": in a reply */
static long id_in(const char *s)
{
    const char *p = strstr(s, "\"id\":");
    return p ? atol(p + 5) : 0;
}

static int count(const char *s, const char *sub)
{
    int k = 0;
    for (; (s = strstr(s, sub)); s++)
        k++;
    return k;
}

int main(void)
{
    char dir[] = "/tmp/npf-admin-XXXXXX", err[300] = "", out[16384], kj[120], sec[NPF_SHARE_SECRET];
    npf_out st = {0};
    npf_t *n;
    int i;
    if (!mkdtemp(dir)) {
        check(0, "a directory");
        return 1;
    }
    put_file(dir, "npf.conf", "root = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\nserver = wss://127.0.0.1:1/v1/ws\n"
                              "server_pub = nvwgWTOBpFl_zXsDesOy2N9KGi56wOLQRngcgZkD_xM\n"
                              "resource = reverse 25200-25210 rev | fixed\n");
    put_file(dir, "node.json", "{\"number\":\"123456789\",\"password\":\"ABCD-EFGH\"}\n");
    /* 150 paired: 0 an admin, 1 one of before the roles, the others members; account 77 the owner; a share code */
    npf_share_parse("K7Q2-ABCD-EFGH", NULL, sec);
    npf_out_printf(&st, "{\"password\":\"pw-123456\",\"owner\":\"77\",\"paired\":[");
    for (i = 0; i < 150; i++) {
        uint8_t k[32];
        char b[NPF_B64_LEN(32)];
        key_of(i, k);
        npf_b64url_encode(k, 32, b);
        npf_out_printf(&st, "%s{\"pub\":\"%s\",\"added\":%d%s}", i ? "," : "", b, 1000 + i,
                       i == 0 ? ",\"role\":\"admin\"" : i == 1 ? "" : ",\"role\":\"member\"");
    }
    npf_out_printf(&st, "],\"shares\":[{\"id\":\"K7Q2\",\"secret\":\"%s\",\"uses\":3,\"expires\":%lld}]}", sec,
                   (long long)time(NULL) + 3600);
    put_file(dir, "state.json", st.p);
    npf_out_free(&st);
    /* local.json: number(0) a saved peer with a service and a forward of its own, number(1) paired before only */
    {
        uint8_t k[32];
        char b[NPF_B64_LEN(32)], lj[1200];
        key_of(7, k);
        b[npf_b64url_encode(k, 32, b)] = 0;
        snprintf(lj, sizeof lj, "{\"devices\": {\"%llu\": {\"save\": true, \"key\": \"%s\", \"forwards\": [{\"kind\": "
                 "\"local\", \"proto\": \"tcp\", \"listen\": \"127.0.0.1\", \"port\": 25301, \"host\": \"127.0.0.1\", "
                 "\"hostport\": 22}], \"resources\": [{\"name\": \"web\", \"type\": \"tcp\", \"svc\": \"http\", "
                 "\"target\": \"127.0.0.1:8080\"}]}, \"%llu\": {\"key\": \"%s\"}}}\n",
                 (unsigned long long)number(0), b, (unsigned long long)number(1), b);
        put_file(dir, "local.json", lj);
    }
    if (!(n = instance(dir, NPF_ROLE_NODE, "udp_port = 0\n", NULL, err, sizeof err)) || !n->callee) {
        printf("     (%s)\n", err);
        check(0, "a node with a number");
        rm_dir(dir);
        return 1;
    }

    /* who may: an admin's paired sessions; a member its role only */
    check(ok(req(n, NPF_AUTH_IK, 0, "admin_get", "{}", out, sizeof out)) && strstr(out, "\"role\":\"admin\"")
              && strstr(out, "\"total\":150") && count(out, "\"key\":") == 100 && count(out, "\"self\":true") == 1
              && count(out, "\"role\":\"admin\"") == 3 && strstr(out, "\"role\":\"member\",\"self\":false"),
          "an admin (IK): admin_get lists a page of 100 members, their roles, itself once");
    check(strstr(out, "\"shares\":[{\"locator\":\"K7Q2\",\"uses\":3,\"expires\":") && !strstr(out, sec) && !strstr(out, "ABCD"),
          "and the share codes: locator, uses, expiry, never the secret");
    check(ok(req(n, NPF_AUTH_IK, 0, "admin_get", "{\"offset\":100}", out, sizeof out)) && strstr(out, "\"total\":150")
              && !strstr(out, "\"self\":true") && strstr(out, "\"since\":1149"), "offset 100: the rest (50)");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_get", "{\"offset\":300}", out, sizeof out), "bad_request"),
          "an offset out of range: bad_request");
    check(ok(req(n, NPF_AUTH_PAKE, 0, "admin_get", "{}", out, sizeof out)) && strstr(out, "\"role\":\"admin\"")
              && ok(req(n, NPF_AUTH_IK, 1, "admin_get", "{}", out, sizeof out)) && strstr(out, "\"total\":150"),
          "an admin's pairing session (PAKE) may too, and one paired before the roles");
    check(ok(req(n, NPF_AUTH_IK, 2, "admin_get", "{}", out, sizeof out)) && is(out, "{\"role\":\"member\"}"),
          "a member: its role only, no members, no codes");
    keyjson(3, kj);
    check(is(req(n, NPF_AUTH_IK, 2, "admin_unpair", kj, out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_IK, 2, "admin_share_new", "{}", out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_IK, 2, "admin_share_del", "{\"locator\":\"K7Q2\"}", out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_IK, 2, "admin_res_del", "{\"name\":\"x\"}", out, sizeof out), "forbidden")
              && n->callee->npaired == 150 && n->callee->nshares == 1,
          "a member's unpair, share codes, resources: forbidden, nothing changed");
    check(is(req(n, NPF_AUTH_GRANT, 0, "admin_get", "{}", out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_DIRECT, 0, "admin_get", "{}", out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_GRANT, 0, "admin_unpair", kj, out, sizeof out), "forbidden"),
          "GRANT and DIRECT sessions with an admin's key: forbidden (a grant, a hosted client, a psk)");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_set", kj, out, sizeof out), "unsupported_type")
              && is(req(n, NPF_AUTH_IK, 0, "admin_transfer", kj, out, sizeof out), "unsupported_type")
              && is(req(n, NPF_AUTH_IK, 0, "admin_unpair", "{\"key\":\"short\"}", out, sizeof out), "bad_request")
              && is(req(n, NPF_AUTH_IK, 0, "admin_unpair", "{}", out, sizeof out), "bad_request"),
          "no role changes (admin_set, admin_transfer unknown); a bad key, none");

    /* unpair: members only */
    keyjson(0, kj);
    check(is(req(n, NPF_AUTH_IK, 0, "admin_unpair", kj, out, sizeof out), "forbidden"), "an admin unpairing itself: forbidden");
    keyjson(1, kj);
    check(is(req(n, NPF_AUTH_IK, 0, "admin_unpair", kj, out, sizeof out), "forbidden") && n->callee->npaired == 150,
          "another admin: forbidden (locally only)");
    keyjson(200, kj);
    check(is(req(n, NPF_AUTH_IK, 0, "admin_unpair", kj, out, sizeof out), "not_found"), "an unknown key: not_found");
    keyjson(149, kj);
    check(ok(req(n, NPF_AUTH_IK, 0, "admin_unpair", kj, out, sizeof out)) && n->callee->npaired == 149,
          "an admin unpairs a member");

    /* resources: as the local command; npf.conf's fixed */
    check(ok(req(n, NPF_AUTH_IK, 0, "admin_res_put",
                 "{\"resource\":{\"name\":\"web\",\"type\":\"tcp\",\"svc\":\"http\",\"target\":\"127.0.0.1:8080\"}}", out,
                 sizeof out)) && n->nres == 2 && strcmp(n->res[1].name, "web") == 0 && n->res[1].persist,
          "admin_res_put publishes (saved, as the command line's)");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_res_put", "{\"resource\":{\"name\":\"rev\",\"type\":\"tcp\",\"target\":"
                                                     "\"127.0.0.1:1\"}}", out, sizeof out), "forbidden")
              && strstr(out, "fixed"), "a fixed resource cannot be replaced: forbidden, the message says why");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_res_put", "{\"resource\":{\"name\":\"x\",\"type\":\"tcp\",\"target\":"
                                                     "\"*\"}}", out, sizeof out), "bad_request")
              && strstr(out, "\"message\":") && n->nres == 2, "a bad resource: bad_request with the reason, nothing published");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_res_del", "{\"name\":\"rev\"}", out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_IK, 0, "admin_res_del", "{\"name\":\"none\"}", out, sizeof out), "not_found")
              && n->nres == 2, "a fixed resource cannot be removed (forbidden), an unknown one is not_found");

    /* share codes */
    check(is(req(n, NPF_AUTH_IK, 0, "admin_share_new", "{\"uses\":2,\"ttl_s\":3600}", out, sizeof out), "offline")
              && n->callee->nshares == 1, "admin_share_new offline: the platform gives the locator");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_share_new", "{\"uses\":101}", out, sizeof out), "bad_request")
              && is(req(n, NPF_AUTH_IK, 0, "admin_share_new", "{\"ttl_s\":2592001}", out, sizeof out), "bad_request")
              && is(req(n, NPF_AUTH_IK, 0, "admin_share_new", "{\"uses\":0}", out, sizeof out), "bad_request"),
          "uses over 100 or 0, a ttl over 30 days: bad_request");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_share_del", "{\"locator\":\"ZZZZ\"}", out, sizeof out), "not_found")
              && ok(req(n, NPF_AUTH_IK, 0, "admin_share_del", "{\"locator\":\"K7Q2\"}", out, sizeof out))
              && n->callee->nshares == 0, "admin_share_del: revoked; an unknown locator not_found");

    /* the code made later goes to the admin's session that asked only: not
     * to another session with that call id (the platform names it) */
    {
        npf_call *c = calloc(1, sizeof *c);
        uint8_t k0[32], k1[32], k2[32];
        key_of(0, k0), key_of(1, k1), key_of(2, k2);
        snprintf(c->call_id_s, sizeof c->call_id_s, "call-1");
        c->st = CS_UP;
        c->next = n->node.calls;
        n->node.calls = c;
        c->auth = NPF_AUTH_IK, memcpy(c->peer_pub, k0, 32);
        check(npf_admin_session_again(n, "call-1", k0) == c && !npf_admin_session_again(n, "call-2", k0),
              "the admin's session that asked: found again by its id");
        c->auth = NPF_AUTH_GRANT;
        check(!npf_admin_session_again(n, "call-1", k0), "the id now a GRANT session with that key: not that admin's");
        c->auth = NPF_AUTH_IK, memcpy(c->peer_pub, k1, 32);
        check(!npf_admin_session_again(n, "call-1", k0), "the id now another admin's session: not the one that asked");
        memcpy(c->peer_pub, k2, 32);
        check(!npf_admin_session_again(n, "call-1", k2), "a member's: never");
        c->st = CS_CLOSED, memcpy(c->peer_pub, k0, 32);
        check(!npf_admin_session_again(n, "call-1", k0), "ended: nobody");
        n->node.calls = c->next;
        free(c);
    }

    /* the log: a line a request, refused ones too, with the caller's
     * fingerprint; 30 a minute, the rest counted in the next minute's first */
    {
        static char lg[NPF_LOG_RING];
        char want[96];
        const char *p;
        uint8_t k3[32];
        key_of(3, k3);
        n->callee->alog_at = 0;
        req(n, NPF_AUTH_IK, 3, "admin_unpair", kj, out, sizeof out);
        for (i = 0; i < 34; i++)
            req(n, NPF_AUTH_IK, 0, "admin_get", "{}", out, sizeof out);
        npf_log_recent(lg, sizeof lg);
        snprintf(want, sizeof want, "admin %016llx: admin_unpair refused (not an admin)",
                 (unsigned long long)npf_fp(k3));
        check((p = strstr(lg, want)) && count(p, "(admin_get)") == 29,
              "the log: a member's refused request with its fingerprint; 30 lines a minute");
        n->callee->alog_at -= 60000;
        req(n, NPF_AUTH_IK, 0, "admin_get", "{}", out, sizeof out);
        npf_log_recent(lg, sizeof lg);
        check(p && (p = strstr(lg, "admin: 5 more requests in that minute not logged")) && count(p, "(admin_get)") == 1,
              "the next minute: how many were not logged, then the lines again");
    }

    /* the node's peers and forwards */
    {
        static char lj_buf[65536];
        char rq[300], by[17], *lj;
        long a, b = 0, f = 0, local_f = 0;
        snprintf(by, sizeof by, "%016llx", (unsigned long long)npf_fp((uint8_t[32]){1, [31] = 0x40}));
        check(is(req(n, NPF_AUTH_IK, 2, "admin_peer_ls", "{}", out, sizeof out), "forbidden")
                  && is(req(n, NPF_AUTH_GRANT, 0, "admin_peer_ls", "{}", out, sizeof out), "forbidden")
                  && is(req(n, NPF_AUTH_IK, 2, "admin_fwd_add", "{\"id\":1,\"target\":\"127.0.0.1:8080\"}", out,
                            sizeof out), "forbidden"),
              "the peers: a member's, a GRANT session's requests forbidden");
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_peer_ls", "{}", out, sizeof out)) && count(out, "\"saved\":") == 1
                  && strstr(out, "\"saved\":true,\"by\":\"\"") && strstr(out, "\"listen\":\"127.0.0.1:25301\"")
                  && (local_f = id_in(strstr(out, "\"forwards\":"))) > 0,
              "admin_peer_ls: the saved peer, added here, with its forward");
        a = id_in(out);
        snprintf(rq, sizeof rq, "{\"number\":%llu}", (unsigned long long)number(0));
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_peer_add", rq, out, sizeof out)) && id_in(out) == a
                  && strstr(out, "\"existing\":true"), "a peer already: its id, existing");
        snprintf(rq, sizeof rq, "{\"number\":%llu}", (unsigned long long)number(2));
        check(is(req(n, NPF_AUTH_IK, 0, "admin_peer_add", rq, out, sizeof out), "need_share"),
              "not paired here, no share code: need_share");
        snprintf(rq, sizeof rq, "{\"number\":%llu,\"share\":\"ABCD-EFGH\"}", (unsigned long long)number(2));
        check(is(req(n, NPF_AUTH_IK, 0, "admin_peer_add", rq, out, sizeof out), "bad_request")
                  && is(req(n, NPF_AUTH_IK, 0, "admin_peer_add", "{\"number\":123456789,\"share\":\"K7Q2-ABCD-EFGH\"}",
                            out, sizeof out), "bad_request")
                  && is(req(n, NPF_AUTH_IK, 0, "admin_peer_add", "{\"number\":123456780}", out, sizeof out), "bad_request"),
              "a password instead of a share code, this node, a bad number: bad_request");
        snprintf(rq, sizeof rq, "{\"number\":%llu,\"name\":\"nas2\"}", (unsigned long long)number(1));
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_peer_add", rq, out, sizeof out)) && strstr(out, "\"existing\":false")
                  && (b = id_in(out)) > 0 && npf_local_by_name(&n->lc, "nas2")
                  && strcmp(npf_local_by_name(&n->lc, "nas2")->by, by) == 0 && npf_local_by_name(&n->lc, "nas2")->save,
              "paired here before: added without a share code, saved, the adder's fingerprint kept");
        for (i = 2; i < 9; i++) {
            snprintf(rq, sizeof rq, "{\"number\":%llu,\"share\":\"K7Q2-ABCD-EFGH\"}", (unsigned long long)number(i));
            if (!ok(req(n, NPF_AUTH_IK, 0, "admin_peer_add", rq, out, sizeof out)))
                break;
        }
        snprintf(rq, sizeof rq, "{\"number\":%llu,\"share\":\"K7Q2-ABCD-EFGH\"}", (unsigned long long)number(9));
        check(i == 9 && is(req(n, NPF_AUTH_IK, 0, "admin_peer_add", rq, out, sizeof out), "limit"),
              "with a share code; 8 added remotely, the 9th: limit");

        /* forwards */
        snprintf(rq, sizeof rq, "{\"id\":%ld,\"target\":\"127.0.0.1:8080\",\"port\":25302}", a);
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", rq, out, sizeof out)) && (f = id_in(out)) > 0
                  && strstr(out, "\"listen\":\"127.0.0.1:"), "admin_fwd_add: a -L on loopback to a service it published");
        snprintf(rq, sizeof rq, "{\"id\":%ld,\"target\":\"127.0.0.1:8080\",\"port\":25303,\"lan\":true}", a);
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", rq, out, sizeof out))
                  && strstr(out, "\"listen\":\"0.0.0.0:"), "lan: on every address (LAN connections only)");
        snprintf(rq, sizeof rq, "{\"id\":%ld,\"target\":\"127.0.0.1:22\"}", a);
        check(is(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", rq, out, sizeof out), "forbidden"),
              "a target it did not publish: forbidden");
        snprintf(rq, sizeof rq, "{\"id\":%ld,\"target\":\"127.0.0.1:8080\",\"port\":80}", a);
        check(is(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", rq, out, sizeof out), "bad_request"), "a port below 1024: bad_request");
        snprintf(rq, sizeof rq, "{\"id\":%ld,\"target\":\"127.0.0.1:8080\"}", b);
        check(is(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", rq, out, sizeof out), "forbidden")
                  && is(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", "{\"id\":9999,\"target\":\"127.0.0.1:8080\"}", out,
                            sizeof out), "not_found"),
              "a peer whose resources were never heard: forbidden; no such peer: not_found");
        for (i = 2; i < 8; i++) {
            snprintf(rq, sizeof rq, "{\"id\":%ld,\"target\":\"127.0.0.1:8080\",\"port\":%d}", a, 25302 + i);
            if (!ok(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", rq, out, sizeof out)))
                break;
        }
        snprintf(rq, sizeof rq, "{\"id\":%ld,\"target\":\"127.0.0.1:8080\",\"port\":25399}", a);
        check(i == 8 && is(req(n, NPF_AUTH_IK, 0, "admin_fwd_add", rq, out, sizeof out), "limit"),
              "8 forwards added remotely on a peer, the 9th: limit");
        lj = file_text(dir, "local.json", lj_buf, sizeof lj_buf);
        check(lj && count(lj, "\"by\": \"") == 8 + 8, "local.json: the adder of each remote peer and forward");
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_peer_ls", "{}", out, sizeof out)) && count(out, "\"by\":\"\"") == 2
                  && count(out, by) == 8 + 8, "admin_peer_ls: who added each");
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_peer_res", (snprintf(rq, sizeof rq, "{\"id\":%ld}", a), rq), out,
                     sizeof out)) && strstr(out, "\"resources\":[{") && strstr(out, "127.0.0.1:8080")
                  && strstr(out, "\"connected\":false"), "admin_peer_res: its services as last heard");
        check(is(req(n, NPF_AUTH_IK, 0, "admin_peer_res", (snprintf(rq, sizeof rq, "{\"id\":%ld}", b), rq), out,
                     sizeof out), "offline"), "never heard: offline");

        /* removing: only what remote admins added */
        check(is(req(n, NPF_AUTH_IK, 0, "admin_fwd_del", (snprintf(rq, sizeof rq, "{\"id\":%ld}", local_f), rq), out,
                     sizeof out), "forbidden")
                  && is(req(n, NPF_AUTH_IK, 0, "admin_peer_del", (snprintf(rq, sizeof rq, "{\"id\":%ld}", a), rq), out,
                            sizeof out), "forbidden"),
              "a forward and a peer added here: forbidden");
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_fwd_del", (snprintf(rq, sizeof rq, "{\"id\":%ld}", f), rq), out,
                     sizeof out))
                  && is(req(n, NPF_AUTH_IK, 0, "admin_fwd_del", rq, out, sizeof out), "not_found"),
              "admin_fwd_del: a forward added remotely; again: not_found");
        check(ok(req(n, NPF_AUTH_IK, 0, "admin_peer_del", (snprintf(rq, sizeof rq, "{\"id\":%ld}", b), rq), out,
                     sizeof out)) && !peer_of(n, (uint32_t)b) && npf_local_by_name(&n->lc, "nas2")
                  && !npf_local_by_name(&n->lc, "nas2")->save && !npf_local_by_name(&n->lc, "nas2")->by[0],
              "admin_peer_del: a peer added remotely, gone (its pinned key and name kept)");

        npf_conf_set(&n->conf, "remote_admin", "members");
        check(is(req(n, NPF_AUTH_IK, 0, "admin_peer_ls", "{}", out, sizeof out), "forbidden"),
              "remote_admin members: the peers refused");
        npf_conf_set(&n->conf, "remote_admin", "on");
    }

    /* remote_admin */
    npf_conf_set(&n->conf, "remote_admin", "members");
    keyjson(148, kj);
    check(is(req(n, NPF_AUTH_IK, 0, "admin_res_del", "{\"name\":\"web\"}", out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_IK, 0, "admin_share_new", "{}", out, sizeof out), "offline")
              && ok(req(n, NPF_AUTH_IK, 0, "admin_unpair", kj, out, sizeof out)) && n->nres == 2 && n->callee->npaired == 148,
          "remote_admin members: resources refused, members and share codes not");
    npf_conf_set(&n->conf, "remote_admin", "off");
    check(is(req(n, NPF_AUTH_IK, 0, "admin_get", "{}", out, sizeof out), "forbidden")
              && is(req(n, NPF_AUTH_IK, 2, "admin_get", "{}", out, sizeof out), "forbidden"),
          "remote_admin off: everything refused, the role too");
    npf_conf_set(&n->conf, "remote_admin", "on");
    check(ok(req(n, NPF_AUTH_IK, 0, "admin_res_del", "{\"name\":\"web\"}", out, sizeof out)) && n->nres == 1,
          "on again: admin_res_del removes it");

    /* no owner: its codes go; whether one is made now is the platform's word (a model
     * device's: yes; offline here); the roles stay */
    check(npf_owner_reset(n) == NPF_OK && n->callee->nshares == 0
              && is(req(n, NPF_AUTH_IK, 0, "admin_share_new", "{}", out, sizeof out), "offline")
              && ok(req(n, NPF_AUTH_IK, 0, "admin_get", "{}", out, sizeof out)) && strstr(out, "\"role\":\"admin\""),
          "no owner (owner reset): the codes gone, admin_share_new asks the platform, the admins stay");

    npf_destroy(n);
    rm_dir(dir);
    printf("%s\n", fails ? "FAILED" : "all passed");
    return fails != 0;
}
