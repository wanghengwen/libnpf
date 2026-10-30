/* The message tables (npf/msg.h, src/node/msgs.c): the tables themselves,
 * the parser's rules on them, the secrets wiped, and signaling.md's ranges
 * of punch_start against its table. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "npf/json.h"
#include "npf/msg.h"
#include "npf/node.h"
#include "msgs.h"
#include "test.h"

static npf_jtok tok[512];
static npf_json j;

static int parse(const npf_msgdesc *d, const char *s, void *out, char *err, size_t cap)
{
    if (npf_json_parse(&j, s, strlen(s), tok, 512) < 0)
        return -2;
    return npf_msg_parse(d, &j, 0, out, err, cap);
}

static size_t bytes(const npf_field *f)
{
    switch (f->type) {
    case NPF_F_STR: case NPF_F_B64: return f->size;
    case NPF_F_INT: return 8;
    case NPF_F_ADDR: return sizeof(struct sockaddr_storage);
    case NPF_F_OBJ: return f->sub->size;
    case NPF_F_ARR: return (size_t)f->size * f->sub->size;
    default: return sizeof(int);
    }
}

/* each table's fields within its struct, apart; lengths where they must be */
static void tables(const npf_msgdesc *d, size_t max)
{
    uint64_t used[1024] = {0};
    int i;
    CHECK(d->nf >= 1 && d->nf <= 64 && d->size <= max, "%s: %d fields, %u bytes", d->name, d->nf, d->size);
    for (i = 0; i < d->nf; i++) {
        const npf_field *f = &d->f[i];
        size_t k, b = bytes(f);
        CHECK(f->key || d->nf == 1, "%s: a field without a key", d->name);
        CHECK(f->off + b <= d->size && (!f->aux || f->aux + sizeof(int) <= d->size), "%s.%s outside", d->name, f->key);
        for (k = f->off; k < f->off + b && k < 1024 * 64; k++) {
            CHECK(!(used[k / 64] & (1ull << (k % 64))), "%s.%s overlaps", d->name, f->key);
            used[k / 64] |= 1ull << (k % 64);
        }
        if (f->type == NPF_F_B64)
            CHECK(f->aux ? f->min >= 1 && f->min <= f->size : (f->flags & NPF_F_REQ) && f->min == f->size,
                  "%s.%s: a length, or required of one length", d->name, f->key);
        if (f->type == NPF_F_ARR)
            CHECK(f->size && f->aux && f->sub, "%s.%s: an array's size, count, elements", d->name, f->key);
        if (f->type == NPF_F_INT)
            CHECK(f->min <= f->max, "%s.%s: a range", d->name, f->key);
        if (f->type == NPF_F_OBJ || f->type == NPF_F_ARR)
            tables(f->sub, max);
    }
}

static void rules(void)
{
    m_punch_start ps;
    m_relay r;
    m_welcome w;
    m_incoming in;
    m_env e;
    m_call_ended ce;
    char err[128], big[600];
    static const char key[] = "q7NcAXdtz5mHUsjvYH0h9Ur3K4YQqsvT8h4mlj_5Ecc";      /* 32 bytes */

    /* signaling.md's punch_start: the values, the defaults of those absent */
    CHECK(parse(&m_punch_start_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"round\":2,\"punch_id\":\"AQIDBAUGBwg\","
                "\"punch_key\":\"q7NcAXdtz5mHUsjvYH0h9Ur3K4YQqsvT8h4mlj_5Ecc\",\"strategy\":\"S3\","
                "\"side\":\"easy\",\"peer\":{\"cand\":[{\"t\":\"srflx\",\"a\":\"198.51.100.7:51234\"},{\"t\":\"host6\","
                "\"a\":\"[2001:db8::7]:9\"},{\"t\":\"x\",\"a\":\"nope\"}],\"pub_ip\":\"198.51.100.7\"},"
                "\"range\":[20480,22527],\"m_total\":1024,\"pps\":200,\"peer_delta\":1,\"start_at\":1791100000300}",
                &ps, err, sizeof err) == 0, "punch_start: %s", err);
    CHECK(ps.round == 2 && ps.punch_id_len == 8 && ps.punch_id[0] == 1 && ps.punch_key_len == 32
          && strcmp(ps.strategy, "S3") == 0 && ps.peer.ncand == 2 && ps.peer.cand[1].a.ss_family == AF_INET6
          && strcmp(ps.peer.pub_ip, "198.51.100.7") == 0 && ps.nrange == 2 && ps.range[1] == 22527 && ps.peer_delta == 1
          && ps.start_at == 1791100000300LL, "punch_start's values");
    CHECK(ps.timeout_ms == 8000 && ps.window == 32 && ps.passes == 4 && ps.n_sockets == 0 && ps.peer_n == 0
          && !ps.skip[0], "punch_start's defaults");
    npf_msg_wipe(&m_punch_start_d, &ps);
    CHECK(ps.punch_key[0] == 0 && ps.punch_key[31] == 0 && ps.punch_id[0] == 1, "punch_key wiped, punch_id kept");

    /* required: missing, wrong, out of range; optional: wrong or out of range is absent; null is absent;
     * unknown keys ignored; an escaped key is the key */
    CHECK(parse(&m_punch_start_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\"}", &ps, err, sizeof err) == -1
          && strcmp(err, "round: missing") == 0, "round missing: %s", err);
    CHECK(parse(&m_punch_start_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"round\":1001}", &ps, err, sizeof err) == -1
          && strstr(err, "round") && strstr(err, "1..1000"), "round out of range: %s", err);
    CHECK(parse(&m_punch_start_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAA\",\"round\":1}", &ps, err, sizeof err) == -1
          && strncmp(err, "call_id:", 8) == 0, "a short call_id: %s", err);
    CHECK(parse(&m_punch_start_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"\\u0072ound\":5,\"pps\":0,\"window\":\"32\","
                "\"start_at\":null,\"range\":[0,9],\"extra\":{\"deep\":[1]}}", &ps, err, sizeof err) == 0
          && ps.round == 5 && ps.pps == 200 && ps.window == 32 && ps.start_at == -1 && ps.nrange == 0,
          "optional fields wrong: their defaults (%s)", err);
    CHECK(parse(&m_punch_start_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"round\":1.5}", &ps, err, sizeof err) == -1,
          "a fraction for an integer");
    CHECK(parse(&m_punch_start_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"round\":1,\"round\":2}", &ps, err, sizeof err) == -2,
          "a duplicate key reached the table");
    CHECK(parse(&m_punch_start_d, "[1]", &ps, err, sizeof err) == -1, "not an object");

    /* the relay: IPv6 addresses left out, the fifth address ignored, ws not a string as missing, a missing key
     * refused, the key wiped */
    snprintf(big, sizeof big, "{\"mode\":\"udp\",\"relay_id\":\"AQIDBAUGBwg\",\"alloc_key\":\"%s\",\"udp\":[\"[::1]:1\","
             "\"1.0.0.1:1\",\"1.0.0.2:2\",\"x\",\"1.0.0.3:3\",\"1.0.0.4:4\",\"1.0.0.5:5\"],\"ws\":{\"server_id\":3}}", key);
    CHECK(parse(&m_relay_d, big, &r, err, sizeof err) == 0 && r.nudp == 4 && r.alloc_key[0] == 0xab && !r.ws[0],
          "relay: %s", err);
    npf_msg_wipe(&m_relay_d, &r);
    CHECK(r.alloc_key[0] == 0 && r.relay_id[0] == 1, "alloc_key wiped");
    CHECK(parse(&m_relay_d, "{\"mode\":\"udp\",\"relay_id\":\"AQIDBAUGBwg\"}", &r, err, sizeof err) == -1
          && strcmp(err, "alloc_key: missing") == 0, "no alloc_key: %s", err);
    snprintf(big, sizeof big, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"auth\":\"ik\",\"hs\":\"AAAA\",\"relay\":{\"mode\":\"udp\","
             "\"relay_id\":\"AQIDBAUGBwg\",\"alloc_key\":\"%.20s\"}}", key);
    CHECK(parse(&m_incoming_d, big, &in, err, sizeof err) == 0 && !in.relay.mode[0] && in.hs_len == 3,
          "an optional relay that does not parse: absent (%s)", err);

    /* the error names the field, never its value (a secret) */
    CHECK(parse(&m_grant_update_d, "{\"grant\":\"q7Nc%AXdtz5m\"}", &w, err, sizeof err) == -1 && strstr(err, "grant")
          && !strstr(err, "q7Nc"), "the error: %s", err);

    /* strings: no control characters; long ones absent, required ones refused */
    CHECK(parse(&m_call_ended_d, "{\"call_id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"reason\":\"a\\nb\"}", &ce, err, sizeof err) == 0
          && !ce.reason[0], "a line break kept");
    CHECK(parse(&m_env_d, "{\"v\":1,\"type\":\"\",\"data\":{}}", &e, err, sizeof err) == -1, "an empty type");
    CHECK(parse(&m_env_d, "{\"v\":2,\"type\":\"x\",\"data\":{}}", &e, err, sizeof err) == -1, "another version");
    CHECK(parse(&m_env_d, "{\"v\":1,\"type\":\"x\",\"data\":[]}", &e, err, sizeof err) == -1, "data not an object");
    CHECK(parse(&m_env_d, "{\"v\":1,\"type\":\"x\",\"message\":\"m\",\"data\":{}}", &e, err, sizeof err) == 0 && e.data > 0
          && strcmp(e.message, "m") == 0 && !e.id[0], "the envelope");

    /* welcome: the probes IPv4 only, a ticket of one length, the day keys wiped */
    snprintf(big, sizeof big, "{\"time\":5,\"ticket\":\"AAAA\",\"probe\":[\"[::1]:1\",\"1.2.3.4:5\"],\"probe_keys\":["
             "{\"day\":1,\"key\":\"%s\"},{\"day\":-1,\"key\":\"%s\"},{\"day\":2,\"key\":\"%s\"},{\"day\":3,\"key\":\"%s\"}]}",
             key, key, key, key);
    CHECK(parse(&m_welcome_d, big, &w, err, sizeof err) == 0 && w.time == 5 && w.server_id == -1 && !w.ticket_len
          && w.nprobe == 1 && w.nprobe_keys == 2 && w.probe_keys[1].day == 2 && w.upgrade == -1 && w.server_list == -1,
          "welcome: %s", err);
    npf_msg_wipe(&m_welcome_d, &w);
    CHECK(w.probe_keys[0].key[0] == 0 && w.probe_keys[1].key[5] == 0 && w.probe_keys[1].day == 2, "the day keys wiped");
}

/* an absent object's fields absent too; a strict optional field refuses
 * the message; a required array is not empty; a boolean's default */
static void more_rules(void)
{
    typedef struct { struct { int t; int64_t i; } o; } nest;
    static const npf_field sub_f[] = {{"t", NPF_F_TOK, 0, 0, 0, 0, 0, 0, 0, NULL},
                                      {"i", NPF_F_INT, 0, 8, 0, 0, 0, 9, 5, NULL}};
    static const npf_msgdesc sub_d = {"sub", sub_f, 2, 16};
    static const npf_field nest_f[] = {{"o", NPF_F_OBJ, 0, 0, 0, 0, 0, 0, 0, &sub_d}};
    static const npf_msgdesc nest_d = {"nest", nest_f, 1, sizeof(nest)};
    nest x;
    m_reverse_listen rl;
    m_list *l = malloc(sizeof *l);
    char err[128];
    CHECK(sizeof x.o == 16 && parse(&nest_d, "{}", &x, err, sizeof err) == 0 && x.o.t == -1 && x.o.i == 5
          && parse(&nest_d, "{\"o\":7}", &x, err, sizeof err) == 0 && x.o.t == -1 && x.o.i == 5,
          "an absent object's fields: %d, %lld", x.o.t, (long long)x.o.i);
    CHECK(parse(&m_reverse_listen_d, "{\"target_host\":\"h\",\"target_port\":22}", &rl, err, sizeof err) == 0
          && !rl.bind[0] && rl.port == 0 && !rl.udp, "reverse_listen's optional fields absent: %s", err);
    CHECK(parse(&m_reverse_listen_d, "{\"target_host\":\"h\",\"target_port\":22,\"udp\":\"true\"}", &rl, err, sizeof err)
          == -1 && strncmp(err, "udp:", 4) == 0, "reverse_listen's udp as a string: %s", err);
    CHECK(parse(&m_reverse_listen_d, "{\"target_host\":\"h\",\"target_port\":22,\"port\":70000}", &rl, err, sizeof err) == -1
          && parse(&m_reverse_listen_d, "{\"target_host\":\"h\",\"target_port\":22,\"bind\":\"a\\tb\"}", &rl, err, sizeof err) == -1,
          "reverse_listen's port, bind wrong");
    CHECK(l != NULL, "memory");
    if (!l)
        return;
    CHECK(parse(&m_list_d, "{\"serial\":1,\"servers\":[{\"id\":1,\"dh_pub\":\"q7NcAXdtz5mHUsjvYH0h9Ur3K4YQqsvT8h4mlj_5Ecc\","
                "\"ws\":[\"\",1]}]}", l, err, sizeof err) == -1 && strncmp(err, "servers:", 8) == 0,
          "a list without a server that has an address: %s", err);
    CHECK(parse(&m_list_d, "{\"serial\":1,\"servers\":[{\"id\":1,\"dh_pub\":\"q7NcAXdtz5mHUsjvYH0h9Ur3K4YQqsvT8h4mlj_5Ecc\","
                "\"ws\":[\"\",\"wss://a/s\"]}]}", l, err, sizeof err) == 0 && l->full == 1 && l->nservers == 1
          && l->servers[0].nws == 1 && l->servers[0].prio == 1 && l->servers[0].weight == 1, "a seed list: %s", err);
    free(l);
}

/* the server list's entries and channels; state.json; local.json's devices */
static void files(void)
{
    static const char list[] =
        "{\"serial\":7,\"full\":false,\"expires\":99,\"servers\":[{\"id\":1,\"dh_pub\":\"AAAA\",\"ws\":[\"wss://x\"]},"
        "{\"id\":2,\"prio\":3,\"weight\":2000,\"kind\":\"cdn\",\"relay\":true,"
        "\"dh_pub\":\"q7NcAXdtz5mHUsjvYH0h9Ur3K4YQqsvT8h4mlj_5Ecc\",\"ws\":[\"wss://a/s\",\"wss://b/s\",\"wss://c/s\"]}],"
        "\"sources\":{\"doh\":[\"seed.example\",\"\"],\"https\":[\"http://no\",\"https://yes/l\"]}}";
    npf_server_entry *e = calloc(NPF_MAX_SERVERS, sizeof *e);
    npf_list_meta meta;
    m_state *st = malloc(sizeof *st);
    m_device *dv = malloc(sizeof *dv);
    int64_t serial = 0;
    char err[128];
    CHECK(e && st && dv, "memory");
    if (!e || !st || !dv)
        goto out;
    CHECK(npf_serverlist_parse(list, strlen(list), e, &serial, &meta) == 1 && serial == 7 && e[0].id == 2
          && e[0].prio == 3 && e[0].weight == 1 && e[0].nws == 2
          && strcmp(e[0].ws[1], "wss://b/s") == 0 && e[0].dh_pub[0] == 0xab, "the servers");
    CHECK(!meta.full && meta.expires == 99 && meta.ndoh == 1 && strcmp(meta.doh[0], "seed.example") == 0
          && meta.nhttps == 1 && strcmp(meta.https[0], "https://yes/l") == 0, "the channels");
    CHECK(npf_serverlist_parse("{\"servers\":[]}", 15, e, &serial, &meta) == -1, "no serial");

    CHECK(parse(&m_state_d, "{\"password\":\"a\\u0001b\",\"paired\":[{\"pub\":\"AAAA\"},{\"pub\":"
                "\"q7NcAXdtz5mHUsjvYH0h9Ur3K4YQqsvT8h4mlj_5Ecc\",\"added\":5}],\"fails\":-1,\"owner\":\"12\","
                "\"revokes\":[{\"account\":\"3\"},{\"account\":\"4\",\"before\":6}]}", st, err, sizeof err) == 0
          && st->password > 0 && st->npaired == 1 && st->paired[0].added == 5 && st->fails == 0
          && strcmp(st->owner, "12") == 0 && st->nrevokes == 1 && st->revokes[0].before == 6, "state.json: %s", err);

    CHECK(parse(&m_device_d, "{\"name\":\"dev\",\"psk\":\"secret\",\"save\":true,\"idle_ms\":-5,\"key\":\"AAAA\","
                "\"forwards\":[\"-L 1\",{\"kind\":\"local\",\"port\":80}],\"mine\":1}", dv, err, sizeof err) == 0
          && dv->save && dv->idle_ms == 0 && !dv->key_len && dv->nforwards == 1 && dv->forwards[0].port == 80
          && dv->resources == -1, "a device: %s", err);
    npf_msg_wipe(&m_device_d, dv);
    CHECK(!dv->psk[0] && strcmp(dv->name, "dev") == 0, "the psk wiped");
out:
    free(e);
    free(st);
    free(dv);
}

/* signaling.md's table of punch_start's optional values is this table */
static void doc_ranges(void)
{
    char line[512], key[32];
    FILE *f = fopen(NPF_LIB_DIR "/docs/protocol/signaling.md", "r");
    int in = 0, seen = 0, i;
    CHECK(f != NULL, "signaling.md");
    if (!f)
        return;
    while (fgets(line, sizeof line, f)) {
        long long lo, hi, def;
        char *p = line, *q;
        if (strstr(line, "当前节点对打洞计划的可选数值按下表解析"))
            in = 1;
        else if (in && seen && line[0] != '|')
            break;
        if (!in || line[0] != '|' || !strchr(line, '`'))
            continue;
        /* | `a`、`b` | lo–hi | def | */
        q = strchr(line + 2, '|');
        if (!q || sscanf(q + 1, " %lld", &lo) != 1 || !(p = strstr(q, "\xe2\x80\x93")) || sscanf(p + 3, "%lld", &hi) != 1
            || !(p = strchr(q + 1, '|')) || sscanf(p + 1, " %lld", &def) != 1)
            continue;
        for (p = line; (p = strchr(p, '`')) && p < q; p = strchr(p + 1, '`') + 1) {
            if (sscanf(p + 1, "%31[a-z_]", key) != 1)
                break;
            for (i = 0; i < m_punch_start_d.nf && strcmp(m_punch_start_d.f[i].key, key) != 0; i++)
                ;
            CHECK(i < m_punch_start_d.nf && m_punch_start_d.f[i].min == lo && m_punch_start_d.f[i].max == hi
                  && m_punch_start_d.f[i].def == def, "signaling.md's %s (%lld-%lld, %lld) is not the table's", key, lo, hi, def);
            seen++;
        }
    }
    fclose(f);
    CHECK(seen == 8, "signaling.md: %d of punch_start's eight optional values", seen);
}

/* "account" (signaling.md): the session's id kept and the program told, a
 * certificate that does not verify left out; an empty one ends the session */
static int account_calls;

static void on_account(npf_node *n, void *arg)
{
    (void)n, (void)arg;
    account_calls++;
}

static void to_node(npf_node *n, const char *s)
{
    if (npf_json_parse(&j, s, strlen(s), tok, 512) == 0)
        node_msg(n, &j);
}

static void account_event(void)
{
    static npf_node node;
    npf_loop *loop = npf_loop_new();
    CHECK(offline_node(&node, loop, NULL, NULL) == 0, "account: set-up");
    if (fails)
        return;
    node.on_account = on_account;
    to_node(&node, "{\"v\":1,\"type\":\"account\",\"data\":{\"account_id\":\"42\",\"account_cert\":\"AAAA\"}}");
    CHECK(node.account_id == 42 && node.account_cert_len == 0 && account_calls == 1,
          "account: the session began (id %llu, a certificate of %zu bytes)", (unsigned long long)node.account_id,
          node.account_cert_len);
    node.account_cert_len = 100;
    to_node(&node, "{\"v\":1,\"type\":\"account\",\"data\":{}}");
    CHECK(node.account_id == 0 && node.account_cert_len == 0 && account_calls == 2, "account: the session ended");
    npf_node_stop(&node);
    npf_loop_free(loop);
}

int test_msg(void)
{
    int i;
    for (i = 0; node_msgdescs[i]; i++)
        tables(node_msgdescs[i], NODE_MSG_MAX);
    for (i = 0; node_filedescs[i]; i++)
        tables(node_filedescs[i], 65536);
    rules();
    more_rules();
    files();
    doc_ranges();
    account_event();
    return fails;
}
