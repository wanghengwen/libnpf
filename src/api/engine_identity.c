/* libnpf: device identity, enrolment and account certificate persistence. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include "engine_internal.h"

/* ---- account certificate (data_dir/account.cert) ---- */

void npf_save_account_cert(npf_t *n)
{
    char out[NPF_B64_LEN(1024) + 2];
    size_t l = npf_b64url_encode(n->node.account_cert, n->node.account_cert_len, out);
    out[l++] = '\n';
    if (npf_file_write(n->cert_path, out, l, 0600) < 0)
        npf_loge("cannot write %s", n->cert_path);
}

void npf_engine_account_load(npf_t *n)
{
    char *s;
    long len = npf_file_read(n->cert_path, &s);
    int r;
    if (len < 0)
        return;
    if (len == 0) {                         /* an empty file: its buffer all the same */
        free(s);
        return;
    }
    s[strcspn(s, "\r\n")] = 0;
    r = npf_b64url_decode(s, strlen(s), n->node.account_cert, sizeof n->node.account_cert);
    n->node.account_cert_len = r > 0 ? (size_t)r : 0;
    free(s);
}

void npf_forget_account(npf_t *n)
{
    unlink(n->cert_path);
    n->node.account_cert_len = 0;
    n->node.account_id = 0;
    n->account_login[0] = 0;
    npf_ev_account(n);
}

static void account_got(npf_node *node, const npf_json *j, int ok, void *arg)
{
    npf_t *n = arg;
    int d;
    (void)node;
    if (!ok || !j || (d = npf_json_get(j, 0, "data")) < 0)
        return;
    if (npf_json_get_str(j, d, "email", n->account_login, sizeof n->account_login) <= 0
        && npf_json_get_str(j, d, "phone", n->account_login, sizeof n->account_login) <= 0)
        npf_json_get_str(j, d, "name", n->account_login, sizeof n->account_login);
}

void npf_account_info(npf_t *n)
{
    n->account_login[0] = 0;
    if (n->node.online && n->node.account_id && !n->cfg.hosted_exec)
        npf_node_request(&n->node, "account_get", "{}", account_got, n);
}

/* ---- identity ---- */

/* one key per device: "NPFD1." + b64url(vendor | product | number | seed | chk) (security.md 4.2) */
static int parse_cred(const char *s, uint64_t *number, uint8_t seed[32])
{
    uint8_t b[64], h[32];
    int r = -1;
    if (strncmp(s, "NPFD1.", 6) == 0 && npf_b64url_decode(s + 6, strlen(s + 6), b, sizeof b) == 52) {
        npf_kdf(h, NULL, 0, b, 48);
        if (memcmp(h, b + 48, 4) == 0) {
            *number = npf_rd64(b + 8);
            memcpy(seed, b + 16, 32);
            r = 0;
        }
    }
    npf_wipe(b, sizeof b);              /* the seed, also when the check failed */
    return r;
}

static void random_password(char out[10])
{
    static const char alpha[] = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    int i, o = 0;
    for (i = 0; i < 8; i++) {
        uint8_t r;
        do {
            npf_random(&r, 1);
        } while (r >= 248);         /* 248 = 8 * 31: no modulo bias */
        if (i == 4)
            out[o++] = '-';
        out[o++] = alpha[r % 31];
    }
    out[o] = 0;
}

/* there, but it cannot be read now (permissions, no descriptors left) */
static int unreadable(const char *path)
{
    struct stat st;
    FILE *f;
    if (stat(path, &st) != 0)
        return errno != ENOENT;
    if (!(f = fopen(path, "rb")))
        return 1;
    fclose(f);
    return 0;
}

/* data_dir/node.json: {"number", "password"} of an enrolled identity */
static int load_node(npf_t *n)
{
    npf_jtok tok[32];
    char *s, num[24];
    long len = npf_file_read(n->node_path, &s);
    npf_json j;
    int ok;
    if (len < 0)
        return -1;
    ok = npf_json_parse(&j, s, (size_t)len, tok, 32) == 0 && npf_json_get_str(&j, 0, "number", num, sizeof num) > 0
         && npf_json_get_str(&j, 0, "password", n->default_pw, sizeof n->default_pw) > 0;
    npf_wipe(s, (size_t)len);           /* the default password */
    free(s);
    if (!ok)
        return -1;
    n->number = strtoull(num, NULL, 10);
    return 0;
}

/* a MAC address the manufacturer burnt in (universally administered), not
 * one made up by the system: a private Wi-Fi address, a bridge, a VM */
static int mac_universal(const char *mac)
{
    return (strtol(mac, NULL, 16) & 0x02) == 0;
}

/* the physical network cards' addresses, sorted, "|"-joined (only the burnt-in
 * ones when there are any: made-up ones change); -1: none */
static int hw_macs(const npf_host_info *hi, char *out, size_t cap)
{
    const char *m[NPF_HOST_MAX_MACS], *t;
    size_t o = 0;
    int i, j, k = 0, uni = 0;
    for (i = 0; i < hi->nmacs; i++)
        uni |= mac_universal(hi->macs[i]);
    for (i = 0; i < hi->nmacs; i++)
        if (!uni || mac_universal(hi->macs[i]))
            m[k++] = hi->macs[i];
    if (k <= 0)
        return -1;
    for (i = 1; i < k; i++)
        for (j = i; j > 0 && strcmp(m[j - 1], m[j]) > 0; j--)
            t = m[j], m[j] = m[j - 1], m[j - 1] = t;
    out[0] = 0;
    for (i = 0; i < k && o < cap; i++)
        o += (size_t)snprintf(out + o, cap - o, "%s%s", i ? "|" : "", m[i]);
    return 0;
}

/* a serial number from the hardware when the vendor gives none: the lowest
 * burnt-in address of the physical network cards ("mac-001132aabbcc"), which survives
 * reinstalling the system; else a hash of the machine id ("mid-" 24 hex) */
static int auto_serial(const npf_host_info *hi, char *out, size_t cap)
{
    const char *low = NULL;
    int i, uni = 0;
    for (i = 0; i < hi->nmacs; i++)
        uni |= mac_universal(hi->macs[i]);
    for (i = 0; i < hi->nmacs; i++)
        if ((!uni || mac_universal(hi->macs[i])) && (!low || strcmp(hi->macs[i], low) < 0))
            low = hi->macs[i];
    if (low) {
        size_t o = (size_t)snprintf(out, cap, "mac-");
        for (; *low && o + 1 < cap; low++)
            if (*low != ':')
                out[o++] = *low;
        out[o] = 0;
        return 0;
    }
    if (hi->machine_id[0]) {
        uint8_t h[32];
        char hex[25];
        npf_kdf(h, NULL, 0, (const uint8_t *)hi->machine_id, strlen(hi->machine_id));
        for (i = 0; i < 12; i++)
            snprintf(hex + 2 * i, 3, "%02x", h[i]);
        snprintf(out, cap, "mid-%s", hex);
        return 0;
    }
    return -1;
}

/* the hardware fingerprint (security.md 5.2): items of the board that stay
 * for its life, each hashed with the model seed, so that a device whose
 * part was replaced still matches most of them (5.3). hw_info "a|b|c": the
 * vendor's items (v1, v2, ...); else the network cards, the eMMC, the board
 * and SoC serials found here; the machine id only when there is nothing else
 * (it changes when the system is reinstalled) */
static int hw_fingerprint(npf_t *n, const npf_host_info *hi, const uint8_t seed[32], char *err, size_t errcap)
{
    npf_hw_item it[8];
    npf_enroll_req *e = &n->enroll;
    const char *cfg = npf_conf_get(&n->conf, "hw_info", NULL);
    uint8_t buf[16 + 8 * (1 + 16 + 16)], h[32];
    size_t o;
    int k = 0, i, j;
    if (cfg) {
        const char *p = cfg;
        while (*p && k < 8) {
            size_t l = strcspn(p, "|");
            snprintf(it[k].kind, sizeof it[k].kind, "v%d", k + 1);
            snprintf(it[k].value, sizeof it[k].value, "%.*s", (int)l, p);
            if (it[k].value[0])
                k++;
            p += l + (p[l] == '|');
        }
    } else {
        if (hw_macs(hi, it[0].value, sizeof it[0].value) == 0)
            snprintf(it[k++].kind, sizeof it[0].kind, "mac");
        k += npf_hw_items(it + k, NPF_HW_MAX);
        if (k == 0 && hi->machine_id[0]) {
            snprintf(it[0].kind, sizeof it[0].kind, "mid");
            snprintf(it[0].value, sizeof it[0].value, "%s", hi->machine_id);
            k = 1;
        }
    }
    if (k == 0) {
        snprintf(err, errcap, "config: no hardware to tell this device by: give 'hw_info'");
        return -1;
    }
    for (i = 1; i < k; i++)                                 /* sorted by kind */
        for (j = i; j > 0 && strcmp(it[j - 1].kind, it[j].kind) > 0; j--) {
            npf_hw_item t = it[j];
            it[j] = it[j - 1];
            it[j - 1] = t;
        }
    memcpy(buf, "npf-hw-v2", 9);
    o = 9;
    for (i = 0; i < k; i++) {
        char v[200];
        size_t kl = strlen(it[i].kind);
        int vl = snprintf(v, sizeof v, "%s%c%s", it[i].kind, 0, it[i].value);
        npf_kdf2(h, seed, 32, "npf hwfp v2", 11, v, (size_t)vl);
        snprintf(e->hw_kind[i], sizeof e->hw_kind[i], "%.*s", (int)sizeof e->hw_kind[i] - 1, it[i].kind);
        memcpy(e->hw_hash[i], h, 16);
        buf[o++] = (uint8_t)kl;
        memcpy(buf + o, it[i].kind, kl);
        o += kl;
        memcpy(buf + o, h, 16);
        o += 16;
    }
    e->nhw = k;
    npf_kdf(e->hw_fp, NULL, 0, buf, o);
    npf_wipe(it, sizeof it);
    return 0;
}

/* one key per model (security.md 4.1, 5.2): the credential (the chain vendor
 * certificate | model certificate, then the model's seed), the serial number
 * (configured, or made from the hardware), the hardware fingerprint
 * BLAKE2b(key = model_seed, "npf hwfp v1" | hw_info) */
static int model_setup(npf_t *n, char *err, size_t errcap)
{
    const char *s = npf_conf_get(&n->conf, "model_cred", NULL), *sf;
    uint8_t b[1200], h[32], seed[32];
    npf_identity mid;
    npf_cert vc, mc;
    npf_host_info hi;
    int len = 0, n1 = -1, n2 = -1;
    if (!s)
        return 0;
    if (strncmp(s, "NPFV2.", 6) == 0 && (len = npf_b64url_decode(s + 6, strlen(s + 6), b, sizeof b)) > 36) {
        n1 = npf_cert_parse(b, (size_t)len - 36, &vc);
        if (n1 > 0)
            n2 = npf_cert_parse(b + n1, (size_t)len - 36 - (size_t)n1, &mc);
    }
    if (n1 <= 0 || n2 <= 0 || n1 + n2 + 36 != len || vc.type != NPF_CERT_VENDOR || mc.type != NPF_CERT_MODEL
        || (npf_kdf(h, NULL, 0, b, (size_t)len - 4), memcmp(h, b + len - 4, 4) != 0)
        || (size_t)(n1 + n2) > sizeof n->enroll.model_chain) {
        snprintf(err, errcap, "config: bad 'model_cred' (an NPFV2 model credential from npf-vendor model)");
        goto fail;
    }
    if (n->has_number) {
        /* enrolled already: the serial number and the fingerprint are for
         * enrolling only (an unreadable serial_file stopped a start that
         * needed neither), the model's key is not needed either */
        n->model_dev = 1;
        goto out;
    }
    n->enroll.model_chain_len = (size_t)(n1 + n2);
    memcpy(n->enroll.model_chain, b, n->enroll.model_chain_len);
    memcpy(seed, b + len - 36, 32);
    npf_identity_from_seed(&mid, seed);
    memcpy(n->enroll.model_sk, mid.sign_sk, 64);
    npf_identity_wipe(&mid);
    npf_host_info_get(&hi);
    if ((sf = npf_conf_get(&n->conf, "serial", NULL)) != NULL) {
        snprintf(n->enroll.serial, sizeof n->enroll.serial, "%s", sf);
    } else if ((sf = npf_conf_get(&n->conf, "serial_file", NULL)) != NULL) {
        char *t;
        if (npf_file_read(sf, &t) < 0) {
            snprintf(err, errcap, "config: cannot read serial_file %s", sf);
            goto fail;
        }
        t[strcspn(t, "\r\n")] = 0;
        snprintf(n->enroll.serial, sizeof n->enroll.serial, "%s", t);
        free(t);
    } else if (auto_serial(&hi, n->enroll.serial, sizeof n->enroll.serial) < 0) {
        snprintf(err, errcap, "config: 'model_cred' needs the device's serial number ('serial' or 'serial_file'): "
                              "this host has neither a network card address nor a machine id");
        goto fail;
    }
    if (!n->enroll.serial[0]) {
        snprintf(err, errcap, "config: the serial number is empty");
        goto fail;
    }
    if (hw_fingerprint(n, &hi, seed, err, errcap) < 0)
        goto fail;
    n->model_dev = 1;
out:
    npf_wipe(seed, sizeof seed);
    npf_wipe(b, sizeof b);
    return 0;
fail:                                       /* the credential and the model's seed wiped on every way out */
    npf_wipe(seed, sizeof seed);
    npf_wipe(b, sizeof b);
    return -1;
}

/* a number for this identity (one key per model, or node_enroll): node.json,
 * the callee state, and callable from now on; pw_out gets the default password */
/* the callee taken onto the node, with the configuration's hosted trust */
void npf_engine_callee_attach(npf_t *n)
{
    n->callee->hosted_trust = atoi(npf_conf_get(&n->conf, "hosted_trust", "1"));
    npf_callee_attach(n->callee, &n->node);
}

int npf_become_node(npf_t *n, uint64_t number)
{
    char pw[10], out[128];
    int len;
    if (!n->callee && !(n->callee = calloc(1, sizeof *n->callee))) {
        npf_loge("no memory for the callee state");
        return -1;                          /* before the number: has_number means a callee (cmd.c) */
    }
    random_password(pw);
    if (npf_callee_init(n->callee, n->state_path, number, n->node.id.seed, pw) < 0) {
        npf_loge("cannot load authorization state %s", n->state_path);
        npf_wipe(pw, sizeof pw);
        return -1;
    }
    len = snprintf(out, sizeof out, "{\"number\":\"%llu\",\"password\":\"%s\"}\n", (unsigned long long)number, pw);
    if (npf_file_write(n->node_path, out, (size_t)len, 0600) < 0) {
        npf_loge("cannot write %s: the number is lost at the next start", n->node_path);
        return -1;
    }
    n->number = number;
    n->has_number = 1;
    /* callable from now on here too, as in the node's own copy (node_signal.c):
     * at each login the callee's work runs (on_login: it never did until a
     * restart, unpairings and an owner reset were not reported) */
    n->cfg.callable = 1;
    n->cfg.number = number;
    snprintf(n->default_pw, sizeof n->default_pw, "%s", pw);
    /* the published resources make the callee's policy now; without it an
     * exit node enrolled at run time refused every internet target until a
     * restart (2026-10-13) */
    npf_pub_apply(n);
    memcpy(n->callee->cert, n->node.cert, n->node.cert_len);
    n->callee->cert_len = n->node.cert_len;
    npf_callee_save(n->callee);
    npf_engine_callee_attach(n);
    npf_wipe(pw, sizeof pw);
    {
        npf_event ev;
        memset(&ev, 0, sizeof ev);
        ev.type = NPF_EV_ENROLLED;
        ev.number = number;
        npf_engine_event(n, &ev, "enrolled", "{\"number\":\"%llu\"}", (unsigned long long)number);
    }
    return 0;
}

/* the identity: a device credential, or data_dir/identity (with node.json and
 * a model credential); the callee state when there is a number */
int npf_engine_identity_load(npf_t *n, char *err, size_t errcap)
{
    char seed_path[1100];
    const char *cred;
    uint8_t seed[32];

    /* the identity: a device credential (read-only), or the key in data_dir/identity */
    cred = npf_conf_get(&n->conf, "cred", NULL);
    if (cred) {
        if (parse_cred(cred, &n->number, seed) < 0) {
            snprintf(err, errcap, "config: bad 'cred' (NPFD1 device credential)");
            return -1;
        }
        n->cred = 1;
        n->has_number = 1;
        snprintf(n->default_pw, sizeof n->default_pw, "%s", npf_conf_get(&n->conf, "password", ""));
        if (!n->default_pw[0]) {
            snprintf(err, errcap, "config: 'password' (the device's default password) goes with 'cred'");
            npf_wipe(seed, sizeof seed);
            return -1;
        }
    } else {
        snprintf(seed_path, sizeof seed_path, "%s/identity", n->data_dir);
        if (npf_seed_file(seed_path, seed, 1) < 0) {
            snprintf(err, errcap, "cannot read or make %s", seed_path);
            return -1;
        }
        n->has_number = load_node(n) == 0;
        if (!n->has_number && unreadable(n->node_path)) {
            /* there but not readable now: not enrolled again over it */
            snprintf(err, errcap, "cannot read %s", n->node_path);
            npf_wipe(seed, sizeof seed);
            return -1;
        }
        if (model_setup(n, err, errcap) < 0) {
            npf_wipe(seed, sizeof seed);
            return -1;
        }
    }
    npf_identity_from_seed(&n->id, seed);
    if (n->has_number) {
        if (!(n->callee = calloc(1, sizeof *n->callee))) {
            npf_wipe(seed, 32);
            snprintf(err, errcap, "no memory");
            return -1;
        }
        if (npf_callee_init(n->callee, n->state_path, n->number, seed, n->default_pw) < 0) {
            npf_wipe(seed, 32);
            snprintf(err, errcap, "cannot load authorization state %s", n->state_path);
            return -1;
        }
    }
    npf_wipe(seed, 32);
    return 0;
}
