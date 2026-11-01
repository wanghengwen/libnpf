/* The admins' requests on a node (security.md D25, src/api/admin.c), the
 * authorization matrix on an instance with a number, not started: an
 * admin's IK and PAKE sessions may (an entry of before the roles is an
 * admin), a member gets its role only and is refused the rest, GRANT and
 * DIRECT sessions are refused even with an admin's key; remote_admin
 * members refuses resources, off everything; paging (100 a page), the
 * share codes listed without their secrets; an admin unpairs members only,
 * not an admin (itself or another); unknown keys, names and locators are
 * not_found, a resource of npf.conf cannot be replaced or removed, a bad
 * resource says why; a share code needs the platform (offline) and an owner
 * (no_owner), its uses and ttl bounded, and the code made later goes only
 * to the session of the admin that asked; there are no role changes. */
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
              && is(req(n, NPF_AUTH_IK, 0, "admin_unpair", "{\"key\":\"short\"}", out, sizeof out), "bad_request"),
          "no role changes (admin_set, admin_transfer unknown); a bad key");

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

    /* no owner: no share code; the roles stay */
    check(npf_owner_reset(n) == NPF_OK && is(req(n, NPF_AUTH_IK, 0, "admin_share_new", "{}", out, sizeof out), "no_owner")
              && ok(req(n, NPF_AUTH_IK, 0, "admin_get", "{}", out, sizeof out)) && strstr(out, "\"role\":\"admin\""),
          "no owner (owner reset): admin_share_new no_owner, the admins stay");

    npf_destroy(n);
    rm_dir(dir);
    printf("%s\n", fails ? "FAILED" : "all passed");
    return fails != 0;
}
