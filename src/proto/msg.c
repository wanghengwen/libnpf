/* Signaling messages checked against their tables (npf/msg.h). */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "npf/crypto.h"
#include "npf/log.h"
#include "npf/msg.h"
#include "npf/node.h"

/* bytes a field takes in its struct (its length or count not counted) */
static size_t field_bytes(const npf_field *f)
{
    switch (f->type) {
    case NPF_F_STR: case NPF_F_B64: return f->size;
    case NPF_F_INT:  return sizeof(int64_t);
    case NPF_F_ADDR: return sizeof(struct sockaddr_storage);
    case NPF_F_OBJ:  return f->sub->size;
    case NPF_F_ARR:  return (size_t)f->size * f->sub->size;
    default:         return sizeof(int);
    }
}

/* the field absent: zero, its length or count 0, an integer its default,
 * a token -1 */
static void absent(const npf_field *f, uint8_t *base)
{
    int none = -1;
    memset(base + f->off, 0, field_bytes(f));
    if (f->aux)
        memset(base + f->aux, 0, sizeof(int));
    if (f->type == NPF_F_INT)
        memcpy(base + f->off, &f->def, sizeof f->def);
    else if (f->type == NPF_F_TOK)
        memcpy(base + f->off, &none, sizeof none);
}

static int bad(char *err, size_t cap, const char *key, const char *why)
{
    if (cap)
        snprintf(err, cap, "%s: %s", key ? key : "item", why);
    return -1;
}

static void set_int(uint8_t *base, uint16_t off, int v)
{
    memcpy(base + off, &v, sizeof v);
}

static int value(const npf_field *f, const npf_json *j, int t, uint8_t *base, char *err, size_t cap);

static int array(const npf_field *f, const npf_json *j, int t, uint8_t *base, char *err, size_t cap)
{
    const npf_msgdesc *e = f->sub;
    int i, n = 0, it = t + 1;
    if (j->tok[t].type != NPF_JT_ARRAY)
        return bad(err, cap, f->key, "not an array");
    for (i = 0; i < j->tok[t].size && n < f->size; i++, it = j->tok[it].next) {
        uint8_t *el = base + f->off + (size_t)n * e->size;
        int r = e->f[0].key ? npf_msg_parse(e, j, it, el, err, cap) : value(&e->f[0], j, it, el, err, cap);
        if (r == 0)
            n++;
        else if (f->flags & NPF_F_SKIP)
            memset(el, 0, e->size);
        else
            return -1;
    }
    set_int(base, f->aux, n);
    return 0;
}

/* the value at token t into its place: 0, or -1 (err says why) */
static int value(const npf_field *f, const npf_json *j, int t, uint8_t *base, char *err, size_t cap)
{
    const npf_jtok *k = &j->tok[t];
    uint8_t *p = base + f->off;
    int64_t v;
    int l;
    switch (f->type) {
    case NPF_F_STR:
        if (k->type != NPF_JT_STRING || (l = npf_json_str(j, t, (char *)p, f->size)) < 0)
            return bad(err, cap, f->key, "not a string, or too long");
        if (!l && (f->flags & NPF_F_REQ))
            return bad(err, cap, f->key, "empty");
        while (l-- > 0)
            if (p[l] < 0x20 || p[l] == 0x7f)
                return bad(err, cap, f->key, "a control character");
        return 0;
    case NPF_F_INT:
        if (npf_json_int(j, t, f->min, f->max, &v) < 0) {
            if (cap)
                snprintf(err, cap, "%s: not an integer in %lld..%lld", f->key, (long long)f->min, (long long)f->max);
            return -1;
        }
        memcpy(p, &v, sizeof v);
        return 0;
    case NPF_F_BOOL:
        return npf_json_bool(j, t, (int *)(void *)p) < 0 ? bad(err, cap, f->key, "not true or false") : 0;
    case NPF_F_B64:
        if (k->type != NPF_JT_STRING || k->escaped
            || (l = npf_b64url_decode(j->s + k->start, k->end - k->start, p, f->size)) < f->min || l < 1)
            return bad(err, cap, f->key, "not base64url of the length wanted");
        if (f->aux)
            set_int(base, f->aux, l);
        return 0;
    case NPF_F_ADDR: {
        char a[80];
        struct sockaddr_storage *ss = (void *)p;
        if (npf_json_str(j, t, a, sizeof a) <= 0 || npf_addr_parse(a, ss) < 0
            || ((f->flags & NPF_F_V4) && ss->ss_family != AF_INET))
            return bad(err, cap, f->key, (f->flags & NPF_F_V4) ? "not an IPv4 address" : "not an address");
        return 0;
    }
    case NPF_F_OBJ: {
        char in[96];
        if (npf_msg_parse(f->sub, j, t, p, in, sizeof in) == 0)
            return 0;
        if (cap)
            snprintf(err, cap, "%s.%s", f->key, in);
        return -1;
    }
    case NPF_F_ARR:
        return array(f, j, t, base, err, cap);
    case NPF_F_TOK:
        if (f->min && k->type != f->min)
            return bad(err, cap, f->key, "of another JSON type");
        set_int(base, f->off, t);
        return 0;
    }
    return bad(err, cap, f->key, "no such type");
}

/* the field of the key at token t (NULL: unknown) */
static int find(const npf_msgdesc *d, const npf_json *j, int t)
{
    const npf_jtok *k = &j->tok[t];
    char buf[64];
    int i;
    if (k->escaped && npf_json_str(j, t, buf, sizeof buf) < 0)
        return -1;
    for (i = 0; i < d->nf; i++)
        if (k->escaped ? strcmp(buf, d->f[i].key) == 0
                       : k->end - k->start == strlen(d->f[i].key) && memcmp(j->s + k->start, d->f[i].key, k->end - k->start) == 0)
            return i;
    return -1;
}

int npf_msg_parse(const npf_msgdesc *d, const npf_json *j, int obj, void *out, char *err, size_t cap)
{
    uint8_t *base = out;
    uint64_t seen = 0;
    int i, t;
    memset(out, 0, d->size);
    if (obj < 0 || obj >= j->ntok || j->tok[obj].type != NPF_JT_OBJECT)
        return bad(err, cap, d->name, "not an object");
    for (i = 0, t = obj + 1; i < j->tok[obj].size; i++, t = j->tok[t + 1].next) {
        int f = find(d, j, t);
        char why[128];
        if (f < 0 || j->tok[t + 1].type == NPF_JT_NULL)
            continue;                           /* unknown, or absent */
        if (value(&d->f[f], j, t + 1, base, why, sizeof why) == 0) {
            seen |= 1ull << f;
            continue;
        }
        absent(&d->f[f], base);
        if (d->f[f].flags & NPF_F_REQ) {
            if (cap)
                snprintf(err, cap, "%s", why);
            return -1;
        }
        npf_logd("%s: %s: ignored", d->name, why);
    }
    for (i = 0; i < d->nf; i++)
        if (!(seen & (1ull << i))) {
            if (d->f[i].flags & NPF_F_REQ)
                return bad(err, cap, d->f[i].key, "missing");
            absent(&d->f[i], base);
        }
    return 0;
}

int npf_msg_data(const npf_msgdesc *d, const npf_json *j, void *out, char *err, size_t cap)
{
    return npf_msg_parse(d, j, j ? npf_json_get(j, 0, "data") : -1, out, err, cap);
}

void npf_msg_wipe(const npf_msgdesc *d, void *msg)
{
    uint8_t *base = msg;
    int i, k;
    for (i = 0; i < d->nf; i++) {
        const npf_field *f = &d->f[i];
        if (f->flags & NPF_F_SECRET)
            npf_wipe(base + f->off, field_bytes(f));
        else if (f->type == NPF_F_OBJ)
            npf_msg_wipe(f->sub, base + f->off);
        else if (f->type == NPF_F_ARR)
            for (k = 0; k < f->size; k++)
                npf_msg_wipe(f->sub, base + f->off + (size_t)k * f->sub->size);
    }
}
