/* The persistent binding's learner (home-binding.md 5): the longest
 * keepalive interval the NAT allows, from the relay's echoes; the packets'
 * bodies; the network's key and home.json. No I/O but home.json's file and
 * the network key's lookups: the unit tests drive the learner with times
 * of their own. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/conf.h"
#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/natprobe.h"
#include "npf/platform.h"

#include "home.h"

/* ---- the packets ---- */

static void st16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void st64(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t ld64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 7; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}

void home_bind_body(uint8_t out[HOME_BIND_BODY], const uint8_t cookie[8], uint64_t kseq, int iv_s, int probe_s,
                    int flags)
{
    memcpy(out, cookie, 8);
    st64(out + 8, kseq);
    st16(out + 16, (uint16_t)iv_s);
    st16(out + 18, (uint16_t)probe_s);
    out[20] = (uint8_t)flags;
}

/* family(1) | port(2) | addr(4/16) | srv_time_ms(8) | state(1) | cookie(8) | kseq(8) | flags(1) */
int home_ack_parse(const uint8_t *b, size_t len, home_ack *a)
{
    size_t alen;
    memset(a, 0, sizeof *a);
    if (len < 1)
        return -1;
    alen = b[0] == 4 ? 4 : b[0] == 6 ? 16 : 0;
    if (!alen || len < 3 + alen + 8 + 1 + 8 + 8 + 1)
        return -1;
    if (alen == 4) {
        a->addr.sin_family = AF_INET;
        a->addr.sin_port = htons((uint16_t)(b[1] | b[2] << 8));
        memcpy(&a->addr.sin_addr, b + 3, 4);
    }
    b += 3 + alen;
    a->srv_ms = (int64_t)ld64(b);
    a->state = b[8];
    memcpy(a->cookie, b + 9, 8);
    a->kseq = ld64(b + 17);
    a->flags = b[25];
    return alen == 4 ? 0 : -1;
}

int home_ping_parse(const uint8_t *b, size_t len, int64_t *srv_ms, int *probe_s, int *n)
{
    if (len < 11)
        return -1;
    *srv_ms = (int64_t)ld64(b);
    *probe_s = b[8] | b[9] << 8;
    *n = b[10];
    return 0;
}

/* ---- the learner ---- */

static const int k_steps[] = {10, 15, 25, 45, 75, 120, 180};
#define NSTEPS ((int)(sizeof k_steps / sizeof k_steps[0]))

void hl_init(hl_state *L, int map, int iv_max, int off)
{
    memset(L, 0, sizeof *L);
    L->map = map;
    L->iv_max = iv_max < HL_IV_MIN ? HL_IV_MIN : iv_max > 300 ? 300 : iv_max;
    L->off = off;
    L->refresh = HL_REFRESH_NONE;
    L->preserve = -1;
}

static int eim(const hl_state *L) { return L->map == NPF_MAP_EIM || L->map == NPF_MAP_UNKNOWN; }

static int clamp_iv(const hl_state *L, int v)
{
    return v < HL_IV_MIN ? HL_IV_MIN : v > L->iv_max ? L->iv_max : v;
}

int hl_iv(const hl_state *L, int track)
{
    const hl_track *t = &L->tr[track == HL_BUSY && eim(L) ? HL_BUSY : HL_QUIET];
    if (L->off)
        return clamp_iv(L, HL_IV_START);
    if (L->mapped)
        return clamp_iv(L, HL_IV_MAPPED);
    if (t->unstable)
        return HL_IV_MIN;
    if (!t->t_ok) {
        if (track == HL_BUSY && eim(L) && L->tr[HL_QUIET].t_ok)
            return hl_iv(L, HL_QUIET);      /* not learned while busy: the quiet one holds there too */
        return t->t_fail && t->t_fail <= HL_IV_START ? HL_IV_MIN : clamp_iv(L, HL_IV_START);
    }
    return clamp_iv(L, t->t_ok * 4 / 5);
}

static int step_above(int s)
{
    int i;
    for (i = 0; i < NSTEPS; i++)
        if (k_steps[i] > s)
            return k_steps[i];
    return 0;
}

static int step_below(int s)
{
    int i;
    for (i = NSTEPS - 1; i >= 0; i--)
        if (k_steps[i] < s)
            return k_steps[i];
    return 0;
}

static void learned(hl_track *t, int64_t now_s)
{
    t->phase = HL_LEARNED;
    t->learned_at = now_s;
    t->up_at = now_s + HL_UP_S;
    t->upping = 0;
}

/* the next wait to try on a track still learning; 0: learned now */
static int track_next(hl_track *t, int64_t now_s)
{
    if (t->doubt)
        return t->doubt;
    if (!t->t_ok) {
        int T;
        if (!t->t_fail)
            return HL_IV_START;             /* 25 first: today's interval */
        t->down = 1;                         /* it failed already: downward, 15 then 10 */
        T = step_below(t->t_fail);
        if (T >= 10)
            return T;
        t->unstable = 1;                     /* not 10 s: the shortest interval */
        learned(t, now_s);
        return 0;
    }
    if (t->t_ok >= HL_TCAP) {
        learned(t, now_s);
        return 0;
    }
    {
        int next = step_above(t->t_ok);
        if (t->t_fail && next >= t->t_fail) {
            if (!t->bisected && t->t_fail - t->t_ok > 15) {
                int mid = (t->t_ok + t->t_fail) / 2 / 5 * 5;
                t->bisected = 1;
                if (mid > t->t_ok && mid < t->t_fail)
                    return mid;
            }
            learned(t, now_s);
            return 0;
        }
        return next;
    }
}

int hl_next(hl_state *L, int track, int64_t now_s, int64_t now_ms, hl_step *st)
{
    hl_track *t;
    int T;
    if (L->off || (L->retry_ms && now_ms < L->retry_ms))
        return 0;
    if (!eim(L))
        track = HL_QUIET;                   /* one track: the flow toward the relay alone counts */
    t = &L->tr[track];
    memset(st, 0, sizeof *st);
    st->track = track;
    if (t->phase != HL_LEARNED) {
        if (t->phase == HL_NEW)
            t->phase = HL_MEASURING;
        if ((T = track_next(t, now_s)) > 0) {
            st->T = T;
            return 1;
        }
    }
    /* learned: the inbound test once (5.5, the quiet track), the day's step upward */
    if (track == HL_QUIET && L->refresh == HL_REFRESH_NONE && t->phase == HL_LEARNED) {
        if (!t->t_fail || t->unstable) {
            L->refresh = HL_REFRESH_UNKNOWN;    /* it never expired: nothing to tell by */
        } else {
            st->T = t->t_fail;
            st->inbound = 1;
            return 1;
        }
    }
    if (t->phase == HL_LEARNED && now_s >= t->up_at) {
        if (t->doubt) {
            st->T = t->doubt;
            return 1;
        }
        T = t->t_fail ? t->t_fail : step_above(t->t_ok);
        if (!T || t->unstable) {
            t->up_at = now_s + HL_UP_S;
            return 0;
        }
        t->upping = 1;
        st->T = T;
        return 1;
    }
    return 0;
}

static void track_ok(hl_track *t, int T)
{
    if (T > t->t_ok)
        t->t_ok = T;
    if (t->t_fail && t->t_fail <= t->t_ok)
        t->t_fail = 0;
    if (t->doubt && t->doubt <= T)
        t->doubt = 0;
    t->unstable = 0;
}

static void track_fail(hl_track *t, int T)
{
    if (T <= t->t_ok) {                     /* shorter than one that lived: the NAT is not what it was */
        t->t_ok = 0;
        t->bisected = t->down = 0;
    }
    if (!t->t_fail || T < t->t_fail)
        t->t_fail = T;
    if (t->doubt == T)
        t->doubt = 0;
}

void hl_done(hl_state *L, const hl_step *st, int outcome, int cls, int64_t now_s, int64_t now_ms)
{
    int multi = eim(L);
    hl_track *q = &L->tr[HL_QUIET], *b = &L->tr[HL_BUSY], *t;
    if (outcome == HL_VOID || cls < 0) {
        L->retry_ms = now_ms + HL_RETRY_MS;
        return;
    }
    if (!multi)
        cls = HL_QUIET;
    t = &L->tr[cls];
    L->retry_ms = 0;
    if (st->inbound) {                      /* 5.5: the ping halfway kept it alive past t_fail, or not */
        if (outcome == HL_OK)
            L->refresh = HL_REFRESH_BOTH;
        else
            L->refresh = HL_REFRESH_OUT;
        return;
    }
    if (outcome == HL_NOECHO) {
        if (t->doubt != st->T) {            /* perhaps an echo lost, or the NAT restarted: once more */
            t->doubt = st->T;
            return;
        }
        L->preserve = 1;                    /* twice with the same address: it came back on the same port */
    } else if (outcome == HL_EXPIRED) {
        L->preserve = 0;
    }
    if (outcome == HL_OK) {
        track_ok(t, st->T);
        if (multi && cls == HL_QUIET)
            track_ok(b, st->T);             /* alive while quiet: alive while busy too */
        if (multi && cls == HL_BUSY && L->per_flow)
            track_ok(q, st->T);             /* a per-flow NAT: busy is as quiet for the relay's flow */
        if (t->phase == HL_LEARNED && t->upping) {
            t->phase = HL_MEASURING;        /* the day's step up went: on upward */
            t->upping = 0;
            t->bisected = 0;
        }
        return;
    }
    /* expired */
    if (multi && cls == HL_BUSY) {          /* other traffic did not keep it: a per-flow NAT */
        if (!L->per_flow && b->t_ok > q->t_ok && b->t_ok < st->T)
            q->t_ok = b->t_ok;              /* what lived while busy lived as if quiet */
        L->per_flow = 1;
        track_fail(b, st->T);
        track_fail(q, st->T);
    } else {
        track_fail(t, st->T);
    }
    if (t->phase == HL_LEARNED) {           /* the day's step up failed */
        t->upping = 0;
        t->up_at = now_s + HL_UP_S;
    }
}

int hl_drops_24h(const hl_state *L, int64_t now_s)
{
    int i, n = 0;
    for (i = 0; i < 3; i++)
        if (L->drops[i] && now_s - L->drops[i] < 86400)
            n++;
    return n;
}

int hl_moved(hl_state *L, int track, int network, int64_t now_s)
{
    hl_track *t;
    int iv, i;
    if (!eim(L))
        track = HL_QUIET;
    t = &L->tr[track];
    if (network || L->off || t->phase != HL_LEARNED)
        return 0;
    iv = hl_iv(L, track);
    for (i = 0; i < 2; i++)
        L->drops[i] = L->drops[i + 1];
    L->drops[2] = now_s;
    if (hl_drops_24h(L, now_s) >= 3) {      /* the third in a day: what was learned does not hold */
        hl_init(L, L->map, L->iv_max, L->off);
        return 2;
    }
    L->mapped = 0;
    t->t_fail = iv;                         /* the interval itself failed: 0.8 of it from now on */
    t->t_ok = iv;
    t->up_at = now_s + HL_UP_S;
    return 1;
}

void hl_mapped(hl_state *L, int64_t now_s)
{
    int i;
    if (L->mapped)
        return;
    L->mapped = 1;
    for (i = 0; i < 2; i++)
        if (L->tr[i].phase != HL_LEARNED) {
            L->tr[i].t_ok = HL_TCAP;        /* taken for granted, confirmed once a day */
            learned(&L->tr[i], now_s);
        }
}

int hl_classify(int map, const npf_udp_watch *w, int64_t start, int64_t end)
{
    int64_t gap;
    if (w->n_relay)
        return -1;                          /* to the relay itself: the step measured nothing */
    if (map == NPF_MAP_APDM)
        return HL_QUIET;                    /* the flow toward the relay alone */
    if (map == NPF_MAP_ADM)
        return w->n_relay_ip ? -1 : HL_QUIET;   /* the relay's IP: its probe servers too */
    if (!w->n_other && !w->n_relay_ip)
        return HL_QUIET;
    gap = w->gap_other;
    if (w->first_other - start > gap)
        gap = w->first_other - start;
    if (end - w->prev_other > gap)
        gap = end - w->prev_other;
    return gap <= HL_BUSY_GAP_MS + 1000 ? HL_BUSY : -1;
}

const char *hl_phase_str(int phase)
{
    return phase == HL_LEARNED ? "learned" : phase == HL_MEASURING ? "measuring" : "new";
}

const char *hl_refresh_str(int refresh)
{
    return refresh == HL_REFRESH_OUT ? "out" : refresh == HL_REFRESH_BOTH ? "both" : "unknown";
}

/* ---- the network's key ---- */

uint64_t home_net_key(uint32_t gw, const char *gw_mac, uint32_t if_net, int if_prefix, uint32_t pub_ip, int cellular)
{
    uint8_t m[64], out[32];
    size_t l = 0, ml = gw_mac ? strlen(gw_mac) : 0;
    uint32_t pub16 = pub_ip & htonl(0xffff0000u);
    uint64_t k = 0;
    int i;
    if (ml > 24)
        ml = 24;
    memcpy(m + l, &gw, 4), l += 4;
    m[l++] = (uint8_t)ml;
    memcpy(m + l, gw_mac, ml), l += ml;
    memcpy(m + l, &if_net, 4), l += 4;
    m[l++] = (uint8_t)if_prefix;
    memcpy(m + l, &pub16, 4), l += 4;
    m[l++] = (uint8_t)(cellular != 0);
    npf_kdf(out, "npf home net", 12, m, l);
    for (i = 0; i < 8; i++)
        k = k << 8 | out[i];
    return k;
}

/* the gateway's MAC address from the ARP table (Linux), "" elsewhere */
static void gw_mac(uint32_t gw, char *out, size_t cap)
{
    out[0] = 0;
#ifdef __linux__
    {
        FILE *f = fopen("/proc/net/arp", "r");
        char line[256], ip[64], mac[64];
        struct in_addr a;
        a.s_addr = gw;
        if (!f)
            return;
        while (fgets(line, sizeof line, f))
            if (sscanf(line, "%63s %*s %*s %63s", ip, mac) == 2 && strcmp(ip, inet_ntoa(a)) == 0) {
                snprintf(out, cap, "%s", mac);
                break;
            }
        fclose(f);
    }
#else
    (void)gw;
    (void)cap;
#endif
}

uint64_t home_net_now(uint32_t pub_ip, int cellular)
{
    uint32_t gw = 0, net = 0;
    int prefix = 0, i, n;
    char mac[64];
    npf_ifaddr ifs[32];
    if (npf_default_gw4(&gw) < 0)
        gw = 0;
    gw_mac(gw, mac, sizeof mac);
    n = npf_if_list(ifs, 32);
    for (i = 0; i < n; i++) {
        uint32_t ip, mask;
        if (ifs[i].family != AF_INET || ifs[i].loopback || ifs[i].prefix <= 0 || ifs[i].prefix > 32)
            continue;
        memcpy(&ip, ifs[i].addr, 4);
        mask = htonl(0xffffffffu << (32 - ifs[i].prefix));
        if (!gw || (ip & mask) == (gw & mask)) {    /* the interface on the default route's network */
            net = ip & mask;
            prefix = ifs[i].prefix;
            if (gw)
                break;
        }
    }
    return home_net_key(gw, mac, net, prefix, pub_ip, cellular);
}

/* ---- home.json ---- */

#define STORE_TOK 2048

static const char *map_name(int m)
{
    return m == NPF_MAP_EIM ? "EIM" : m == NPF_MAP_ADM ? "ADM" : m == NPF_MAP_APDM ? "APDM" : "UNKNOWN";
}

static int map_of(const char *s)
{
    return strcmp(s, "EIM") == 0 ? NPF_MAP_EIM : strcmp(s, "ADM") == 0 ? NPF_MAP_ADM
           : strcmp(s, "APDM") == 0 ? NPF_MAP_APDM : NPF_MAP_UNKNOWN;
}

static void write_track(npf_jw *w, const char *k, const hl_track *t)
{
    npf_jw_key(w, k);
    npf_jw_obj(w);
    npf_jw_kint(w, "phase", t->phase == HL_LEARNED ? HL_LEARNED : t->t_ok || t->t_fail ? HL_MEASURING : HL_NEW);
    npf_jw_kint(w, "t_ok", t->t_ok);
    npf_jw_kint(w, "t_fail", t->t_fail);
    npf_jw_kint(w, "bisected", t->bisected);
    npf_jw_kint(w, "unstable", t->unstable);
    npf_jw_kint(w, "at", t->learned_at);
    npf_jw_kint(w, "up", t->up_at);
    npf_jw_end(w);
}

static void read_track(const npf_json *j, int o, hl_track *t)
{
    int64_t v;
    memset(t, 0, sizeof *t);
    if (o < 0)
        return;
    if (npf_json_get_int(j, o, "phase", 0, 2, &v) == 0)
        t->phase = (int)v;
    if (npf_json_get_int(j, o, "t_ok", 0, 600, &v) == 0)
        t->t_ok = (int)v;
    if (npf_json_get_int(j, o, "t_fail", 0, 600, &v) == 0)
        t->t_fail = (int)v;
    if (npf_json_get_int(j, o, "bisected", 0, 1, &v) == 0)
        t->bisected = (int)v;
    if (npf_json_get_int(j, o, "unstable", 0, 1, &v) == 0)
        t->unstable = (int)v;
    if (npf_json_get_int(j, o, "at", 0, INT64_MAX, &v) == 0)
        t->learned_at = v;
    if (npf_json_get_int(j, o, "up", 0, INT64_MAX, &v) == 0)
        t->up_at = v;
    if (t->phase == HL_LEARNED && !t->t_ok && !t->unstable)
        t->phase = HL_NEW;                  /* nothing to go by */
}

/* one network's record into w */
static void write_net(npf_jw *w, uint64_t key, const hl_state *L, int64_t used)
{
    char k[24];
    int i;
    snprintf(k, sizeof k, "%016llx", (unsigned long long)key);
    npf_jw_obj(w);
    npf_jw_kstr(w, "key", k);
    npf_jw_kint(w, "used", used);
    npf_jw_kstr(w, "map", map_name(L->map));
    write_track(w, "quiet", &L->tr[HL_QUIET]);
    write_track(w, "busy", &L->tr[HL_BUSY]);
    npf_jw_kint(w, "refresh", L->refresh);
    npf_jw_kint(w, "preserve", L->preserve);
    npf_jw_kint(w, "per_flow", L->per_flow);
    npf_jw_key(w, "drops");
    npf_jw_arr(w);
    for (i = 0; i < 3; i++)
        npf_jw_int(w, L->drops[i]);
    npf_jw_end(w);
    npf_jw_end(w);
}

/* a record of j into L (its iv_max, off and mapped stay the caller's) */
static void read_net(const npf_json *j, int o, hl_state *L)
{
    char m[16] = "";
    int64_t v;
    int a, i;
    npf_json_get_str(j, o, "map", m, sizeof m);
    L->map = map_of(m);
    read_track(j, npf_json_get(j, o, "quiet"), &L->tr[HL_QUIET]);
    read_track(j, npf_json_get(j, o, "busy"), &L->tr[HL_BUSY]);
    L->refresh = npf_json_get_int(j, o, "refresh", 0, 3, &v) == 0 ? (int)v : HL_REFRESH_NONE;
    L->preserve = npf_json_get_int(j, o, "preserve", -1, 1, &v) == 0 ? (int)v : -1;
    L->per_flow = npf_json_get_int(j, o, "per_flow", 0, 1, &v) == 0 && v;
    a = npf_json_get(j, o, "drops");
    for (i = 0; a >= 0 && i < 3 && i < j->tok[a].size; i++)
        if (npf_json_int(j, npf_json_item(j, a, i), 0, INT64_MAX, &v) == 0)
            L->drops[i] = v;
}

/* the file's records, parsed (j over buf, the "nets" array) */
static int store_open(const char *path, char **buf, npf_json *j, npf_jtok *tok)
{
    long len;
    int arr;
    *buf = NULL;
    if (!path || (len = npf_file_read(path, buf)) < 0)
        return -1;
    if (npf_json_parse_file(j, *buf, (size_t)len, tok, STORE_TOK) < 0 || j->tok[0].type != NPF_JT_OBJECT
        || (arr = npf_json_get(j, 0, "nets")) < 0 || j->tok[arr].type != NPF_JT_ARRAY) {
        free(*buf);
        *buf = NULL;
        return -1;                          /* damaged: as if there were none (it is learned again) */
    }
    return arr;
}

static uint64_t rec_key(const npf_json *j, int o)
{
    char k[24];
    if (npf_json_get_str(j, o, "key", k, sizeof k) != 16)
        return 0;
    return strtoull(k, NULL, 16);
}

int home_store_load(const char *path, uint64_t key, hl_state *L, int64_t *used)
{
    npf_jtok *tok = malloc(STORE_TOK * sizeof *tok);
    npf_json j;
    char *buf;
    int arr, i, found = -1;
    if (!tok)
        return -1;
    if ((arr = store_open(path, &buf, &j, tok)) >= 0) {
        for (i = 0; i < j.tok[arr].size && found < 0; i++) {
            int o = npf_json_item(&j, arr, i);
            int64_t v = 0;
            if (o >= 0 && j.tok[o].type == NPF_JT_OBJECT && rec_key(&j, o) == key) {
                read_net(&j, o, L);
                npf_json_get_int(&j, o, "used", 0, INT64_MAX, &v);
                if (used)
                    *used = v;
                found = 0;
            }
        }
        free(buf);
    }
    free(tok);
    return found;
}

int home_store_save(const char *path, uint64_t key, const hl_state *L, int64_t now_s)
{
    npf_jtok *tok = malloc(STORE_TOK * sizeof *tok);
    size_t cap = 16384;
    char *out = malloc(cap), *buf = NULL;
    npf_json j;
    npf_jw w;
    int arr, i, n, kept = 1, r = -1;
    if (!tok || !out || !path)
        goto done;
    arr = store_open(path, &buf, &j, tok);
    npf_jw_init(&w, out, cap);
    npf_jw_obj(&w);
    npf_jw_kint(&w, "v", 1);
    npf_jw_key(&w, "nets");
    npf_jw_arr(&w);
    write_net(&w, key, L, now_s);
    /* the others, the most recently used first, HOME_NETS_MAX in all */
    n = arr >= 0 ? j.tok[arr].size : 0;
    while (kept < HOME_NETS_MAX) {
        int best = -1;
        int64_t bu = -1;
        for (i = 0; i < n; i++) {
            int o = npf_json_item(&j, arr, i);
            int64_t u = 0;
            if (o < 0 || j.tok[o].type != NPF_JT_OBJECT || !rec_key(&j, o) || rec_key(&j, o) == key)
                continue;
            npf_json_get_int(&j, o, "used", 0, INT64_MAX, &u);
            if (u > bu) {
                bu = u;
                best = i;
            }
        }
        if (best < 0)
            break;
        {
            int o = npf_json_item(&j, arr, best);
            hl_state x;
            hl_init(&x, NPF_MAP_UNKNOWN, L->iv_max, 0);
            read_net(&j, o, &x);
            write_net(&w, rec_key(&j, o), &x, bu);
            /* taken: its key no longer matches (the copy in buf is not written again) */
            j.tok[npf_json_get(&j, o, "key")].end = j.tok[npf_json_get(&j, o, "key")].start;
        }
        kept++;
    }
    npf_jw_end(&w);
    npf_jw_end(&w);
    if (npf_jw_finish(&w) > 0)
        r = npf_file_write(path, out, w.len, 0600);
done:
    free(buf);
    free(tok);
    free(out);
    return r;
}
