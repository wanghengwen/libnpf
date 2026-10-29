#include <string.h>

#include "npf/crypto.h"
#include "npf/json.h"
#include "npf/text.h"

typedef struct parser {
    npf_json *j;
    size_t    pos;
    int       depth;
} parser;

static void skip_ws(parser *p)
{
    while (p->pos < p->j->len) {
        char c = p->j->s[p->pos];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            break;
        p->pos++;
    }
}

static int new_tok(parser *p, int type, size_t start)
{
    npf_jtok *t;
    if (p->j->ntok >= p->j->cap)
        return -1;
    t = &p->j->tok[p->j->ntok];
    memset(t, 0, sizeof *t);
    t->type = (uint8_t)type;
    t->start = (uint32_t)start;
    return p->j->ntok++;
}

/* the token t ends here: its end and the token after its subtree */
static int tok_done(parser *p, int t)
{
    p->j->tok[t].end = (uint32_t)p->pos;
    p->j->tok[t].next = p->j->ntok;
    return t;
}

/* the four hex digits at s (all in the buffer), -1 if they are not */
static int hex4(const unsigned char *s)
{
    int k, v = 0;
    for (k = 0; k < 4; k++) {
        int h = npf_hexval(s[k]);
        if (h < 0)
            return -1;
        v = v << 4 | h;
    }
    return v;
}

/* one UTF-8 sequence at s[i]; returns its length or -1 */
static int utf8_len(const unsigned char *s, size_t n, size_t i)
{
    unsigned c = s[i];
    unsigned cp;
    int len, k;
    if (c < 0x80) return 1;
    if (c >= 0xc2 && c <= 0xdf) { len = 2; cp = c & 0x1f; }
    else if (c >= 0xe0 && c <= 0xef) { len = 3; cp = c & 0x0f; }
    else if (c >= 0xf0 && c <= 0xf4) { len = 4; cp = c & 0x07; }
    else return -1;
    if (i + (size_t)len > n) return -1;
    for (k = 1; k < len; k++) {
        if ((s[i + k] & 0xc0) != 0x80) return -1;
        cp = (cp << 6) | (s[i + k] & 0x3f);
    }
    if ((len == 3 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) || (len == 4 && (cp < 0x10000 || cp > 0x10ffff)))
        return -1;
    return len;
}

static int parse_string(parser *p)
{
    const unsigned char *s = (const unsigned char *)p->j->s;
    size_t n = p->j->len;
    int t = new_tok(p, NPF_JT_STRING, p->pos + 1);
    if (t < 0)
        return -1;
    p->pos++;
    while (p->pos < n) {
        unsigned c = s[p->pos];
        if (c == '"') {
            tok_done(p, t);
            p->pos++;
            return t;
        }
        if (c < 0x20)
            return -1;
        if (c == '\\') {
            p->j->tok[t].escaped = 1;
            if (++p->pos >= n)
                return -1;
            c = s[p->pos];
            if (c == 'u') {
                int v, lo;
                if (p->pos + 4 >= n || (v = hex4(s + p->pos + 1)) < 0)
                    return -1;
                p->pos += 5;
                if (v >= 0xd800 && v <= 0xdbff) {       /* must be followed by a low surrogate */
                    if (p->pos + 5 >= n || s[p->pos] != '\\' || s[p->pos + 1] != 'u'
                        || (lo = hex4(s + p->pos + 2)) < 0xdc00 || lo > 0xdfff)
                        return -1;
                    p->pos += 6;
                } else if (v >= 0xdc00 && v <= 0xdfff) {
                    return -1;
                }
                continue;
            }
            if (!strchr("\"\\/bfnrt", (int)c) || c == 0)
                return -1;
            p->pos++;
            continue;
        }
        {
            int l = utf8_len(s, n, p->pos);
            if (l < 0)
                return -1;
            p->pos += (size_t)l;
        }
    }
    return -1;
}

/* the digits from pos on; how many */
static size_t digits(parser *p)
{
    size_t st = p->pos;
    while (p->pos < p->j->len && p->j->s[p->pos] >= '0' && p->j->s[p->pos] <= '9')
        p->pos++;
    return p->pos - st;
}

/* -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)? */
static int parse_number(parser *p)
{
    const char *s = p->j->s;
    size_t n = p->j->len;
    int t = new_tok(p, NPF_JT_NUMBER, p->pos);
    if (t < 0)
        return -1;
    if (p->pos < n && s[p->pos] == '-')
        p->pos++;
    if (p->pos < n && s[p->pos] == '0')
        p->pos++;
    else if (!digits(p))
        return -1;
    if (p->pos < n && s[p->pos] == '.') {
        p->pos++;
        if (!digits(p))
            return -1;
    }
    if (p->pos < n && (s[p->pos] == 'e' || s[p->pos] == 'E')) {
        p->pos++;
        if (p->pos < n && (s[p->pos] == '+' || s[p->pos] == '-'))
            p->pos++;
        if (!digits(p))
            return -1;
    }
    return tok_done(p, t);
}

static int parse_value(parser *p);

/* a string token as it reads unescaped: its length and *s its text (the
 * input's, else x); -1 escaped and longer than x, or a NUL in it */
static int str_view(const npf_json *j, int t, char x[256], const char **s)
{
    const npf_jtok *k = &j->tok[t];
    if (!k->escaped) {
        *s = j->s + k->start;
        return (int)(k->end - k->start);
    }
    *s = x;
    return npf_json_str(j, t, x, 256);
}

/* two string tokens equal after unescaping? (one str_view refuses: a
 * clash, the message is rejected) */
static int key_equal(const npf_json *j, int a, int b)
{
    char x[256], y[256];
    const char *s, *u;
    int n = str_view(j, a, x, &s), m = str_view(j, b, y, &u);
    return n < 0 || m < 0 || (n == m && memcmp(s, u, (size_t)n) == 0);
}

/* FNV-1a of a key as it reads unescaped; -1: str_view refuses it */
static int key_hash(const npf_json *j, int k, uint32_t *out)
{
    const char *s;
    char x[256];
    int n = str_view(j, k, x, &s), i;
    uint32_t h = 2166136261u;
    if (n < 0)
        return -1;
    for (i = 0; i < n; i++)
        h = (h ^ (unsigned char)s[i]) * 16777619u;
    *out = h;
    return 0;
}

static int parse_container(parser *p, int is_obj)
{
    npf_json *j = p->j;
    int t = new_tok(p, is_obj ? NPF_JT_OBJECT : NPF_JT_ARRAY, p->pos);
    int count = 0;
    uint32_t kh[NPF_JSON_MAX_ARRAY];    /* the keys' hashes: each unescaped once, compared only on a match */
    if (t < 0 || ++p->depth > NPF_JSON_MAX_DEPTH)
        return -1;
    p->pos++;
    skip_ws(p);
    if (p->pos < j->len && j->s[p->pos] == (is_obj ? '}' : ']')) {
        p->pos++;
        goto done;
    }
    for (;;) {
        if (count >= NPF_JSON_MAX_ARRAY)
            return -1;
        skip_ws(p);
        if (is_obj) {
            int k, i, prev;
            uint32_t h;
            if (p->pos >= j->len || j->s[p->pos] != '"')
                return -1;
            k = parse_string(p);
            if (k < 0 || key_hash(j, k, &h) < 0)
                return -1;
            /* the earlier keys: t + 1, then each one's value's next */
            for (i = 0, prev = t + 1; i < count; i++, prev = j->tok[prev + 1].next)
                if (kh[i] == h && key_equal(j, prev, k))
                    return -1;
            kh[count] = h;
            skip_ws(p);
            if (p->pos >= j->len || j->s[p->pos] != ':')
                return -1;
            p->pos++;
            skip_ws(p);
        }
        if (parse_value(p) < 0)
            return -1;
        count++;
        skip_ws(p);
        if (p->pos >= j->len)
            return -1;
        if (j->s[p->pos] == ',') {
            p->pos++;
            continue;
        }
        if (j->s[p->pos] == (is_obj ? '}' : ']')) {
            p->pos++;
            break;
        }
        return -1;
    }
done:
    p->depth--;
    j->tok[t].size = (uint16_t)count;
    return tok_done(p, t);
}

static int parse_lit(parser *p, const char *lit, int type)
{
    size_t l = strlen(lit);
    int t;
    if (p->pos + l > p->j->len || memcmp(p->j->s + p->pos, lit, l) != 0)
        return -1;
    t = new_tok(p, type, p->pos);
    if (t < 0)
        return -1;
    p->pos += l;
    return tok_done(p, t);
}

static int parse_value(parser *p)
{
    char c;
    skip_ws(p);
    if (p->pos >= p->j->len)
        return -1;
    c = p->j->s[p->pos];
    switch (c) {
    case '{': return parse_container(p, 1);
    case '[': return parse_container(p, 0);
    case '"': return parse_string(p);
    case 't': return parse_lit(p, "true", NPF_JT_TRUE);
    case 'f': return parse_lit(p, "false", NPF_JT_FALSE);
    case 'n': return parse_lit(p, "null", NPF_JT_NULL);
    default:
        if (c == '-' || (c >= '0' && c <= '9'))
            return parse_number(p);
        return -1;
    }
}

static int parse_max(npf_json *j, const char *s, size_t len, npf_jtok *tok, int cap, size_t max)
{
    parser p;
    j->s = s;
    j->len = len;
    j->tok = tok;
    j->cap = cap;
    j->ntok = 0;
    if (len > max)
        return -1;
    p.j = j;
    p.pos = 0;
    p.depth = 0;
    if (parse_value(&p) < 0)
        return -1;
    skip_ws(&p);
    return p.pos == len ? 0 : -1;
}

int npf_json_parse(npf_json *j, const char *s, size_t len, npf_jtok *tok, int cap)
{
    return parse_max(j, s, len, tok, cap, NPF_JSON_MAX_SIZE);
}

int npf_json_parse_file(npf_json *j, const char *s, size_t len, npf_jtok *tok, int cap)
{
    return parse_max(j, s, len, tok, cap, NPF_JSON_MAX_FILE);
}

/* token t, if there is one of that type (0: any) */
static const npf_jtok *tok_of(const npf_json *j, int t, int type)
{
    return t >= 0 && t < j->ntok && (!type || j->tok[t].type == type) ? &j->tok[t] : NULL;
}

int npf_json_get(const npf_json *j, int obj, const char *key)
{
    int i, t;
    size_t kl = strlen(key);
    if (!tok_of(j, obj, NPF_JT_OBJECT))
        return -1;
    t = obj + 1;
    for (i = 0; i < j->tok[obj].size; i++) {
        char x[256];
        const char *s;
        int v = t + 1, n = str_view(j, t, x, &s);
        if (n >= 0 && (size_t)n == kl && memcmp(s, key, kl) == 0)
            return v;
        t = j->tok[v].next;
    }
    return -1;
}

int npf_json_item(const npf_json *j, int arr, int i)
{
    int t, k;
    if (!tok_of(j, arr, NPF_JT_ARRAY) || i < 0 || i >= j->tok[arr].size)
        return -1;
    t = arr + 1;
    for (k = 0; k < i; k++)
        t = j->tok[t].next;
    return t;
}

static size_t put_utf8(char *o, unsigned cp)
{
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xc0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 0x3f)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xe0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        o[2] = (char)(0x80 | (cp & 0x3f)); return 3;
    }
    o[0] = (char)(0xf0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3f)); o[3] = (char)(0x80 | (cp & 0x3f)); return 4;
}

int npf_json_str(const npf_json *j, int t, char *buf, size_t cap)
{
    const npf_jtok *k = tok_of(j, t, NPF_JT_STRING);
    size_t i, o = 0;
    if (!k || cap == 0)
        return -1;
    for (i = k->start; i < k->end;) {
        char tmp[4];
        size_t l = 1;
        char c = j->s[i];
        if (c != '\\') {
            tmp[0] = c;
            i++;
        } else {
            c = j->s[i + 1];
            i += 2;
            switch (c) {
            case 'b': tmp[0] = '\b'; break;
            case 'f': tmp[0] = '\f'; break;
            case 'n': tmp[0] = '\n'; break;
            case 'r': tmp[0] = '\r'; break;
            case 't': tmp[0] = '\t'; break;
            case 'u': {                 /* checked by the parser */
                unsigned v = (unsigned)hex4((const unsigned char *)j->s + i);
                i += 4;
                if (v >= 0xd800 && v <= 0xdbff) {
                    unsigned lo = (unsigned)hex4((const unsigned char *)j->s + i + 2);
                    i += 6;
                    v = 0x10000 + ((v - 0xd800) << 10) + (lo - 0xdc00);
                }
                if (v == 0)
                    return -1;
                l = put_utf8(tmp, v);
                break;
            }
            default: tmp[0] = c;
            }
        }
        if (o + l >= cap)
            return -1;
        memcpy(buf + o, tmp, l);
        o += l;
    }
    buf[o] = 0;
    return (int)o;
}

int npf_json_eq(const npf_json *j, int t, const char *lit)
{
    size_t l = strlen(lit);
    const npf_jtok *k = tok_of(j, t, NPF_JT_STRING);
    if (!k || k->escaped)
        return 0;
    return k->end - k->start == l && memcmp(j->s + k->start, lit, l) == 0;
}

int npf_json_int(const npf_json *j, int t, int64_t min, int64_t max, int64_t *out)
{
    const npf_jtok *k = tok_of(j, t, NPF_JT_NUMBER);
    size_t i;
    int neg = 0;
    uint64_t v = 0;
    if (!k)
        return -1;
    i = k->start;
    if (j->s[i] == '-') { neg = 1; i++; }
    for (; i < k->end; i++) {
        char c = j->s[i];
        if (c < '0' || c > '9')
            return -1;                  /* fraction or exponent */
        if (v > (UINT64_MAX - 9) / 10)
            return -1;
        v = v * 10 + (uint64_t)(c - '0');
    }
    if (!neg && v > (uint64_t)INT64_MAX)
        return -1;
    if (neg && v > (uint64_t)INT64_MAX + 1)
        return -1;
    {
        int64_t s = neg ? (int64_t)(0 - v) : (int64_t)v;
        if (s < min || s > max)
            return -1;
        *out = s;
    }
    return 0;
}

int npf_json_bool(const npf_json *j, int t, int *out)
{
    const npf_jtok *k = tok_of(j, t, 0);
    if (!k || (k->type != NPF_JT_TRUE && k->type != NPF_JT_FALSE))
        return -1;
    *out = k->type == NPF_JT_TRUE;
    return 0;
}

int npf_json_b64(const npf_json *j, int t, uint8_t *out, size_t cap)
{
    const npf_jtok *k = tok_of(j, t, NPF_JT_STRING);
    if (!k || k->escaped)
        return -1;
    return npf_b64url_decode(j->s + k->start, k->end - k->start, out, cap);
}

int npf_json_get_str(const npf_json *j, int obj, const char *key, char *buf, size_t cap)
{
    return npf_json_str(j, npf_json_get(j, obj, key), buf, cap);
}

int npf_json_get_int(const npf_json *j, int obj, const char *key, int64_t min, int64_t max, int64_t *out)
{
    return npf_json_int(j, npf_json_get(j, obj, key), min, max, out);
}

int npf_json_get_b64(const npf_json *j, int obj, const char *key, uint8_t *out, size_t cap)
{
    return npf_json_b64(j, npf_json_get(j, obj, key), out, cap);
}
