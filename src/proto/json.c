#include <string.h>

#include "npf/crypto.h"
#include "npf/json.h"

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

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
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
            p->j->tok[t].end = (uint32_t)p->pos;
            p->pos++;
            p->j->tok[t].next = p->j->ntok;
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
                unsigned v = 0;
                int k;
                if (p->pos + 4 >= n)
                    return -1;
                for (k = 1; k <= 4; k++) {
                    int h = hexv((char)s[p->pos + k]);
                    if (h < 0)
                        return -1;
                    v = (v << 4) | (unsigned)h;
                }
                p->pos += 5;
                if (v >= 0xd800 && v <= 0xdbff) {       /* must be followed by a low surrogate */
                    unsigned lo = 0;
                    if (p->pos + 5 >= n || s[p->pos] != '\\' || s[p->pos + 1] != 'u')
                        return -1;
                    for (k = 2; k <= 5; k++) {
                        int h = hexv((char)s[p->pos + k]);
                        if (h < 0)
                            return -1;
                        lo = (lo << 4) | (unsigned)h;
                    }
                    if (lo < 0xdc00 || lo > 0xdfff)
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

static int parse_number(parser *p)
{
    const char *s = p->j->s;
    size_t n = p->j->len, st = p->pos;
    int t = new_tok(p, NPF_JT_NUMBER, st);
    if (t < 0)
        return -1;
    if (p->pos < n && s[p->pos] == '-') p->pos++;
    if (p->pos >= n) return -1;
    if (s[p->pos] == '0') {
        p->pos++;
    } else if (s[p->pos] >= '1' && s[p->pos] <= '9') {
        while (p->pos < n && s[p->pos] >= '0' && s[p->pos] <= '9') p->pos++;
    } else {
        return -1;
    }
    if (p->pos < n && s[p->pos] == '.') {
        p->pos++;
        if (p->pos >= n || s[p->pos] < '0' || s[p->pos] > '9') return -1;
        while (p->pos < n && s[p->pos] >= '0' && s[p->pos] <= '9') p->pos++;
    }
    if (p->pos < n && (s[p->pos] == 'e' || s[p->pos] == 'E')) {
        p->pos++;
        if (p->pos < n && (s[p->pos] == '+' || s[p->pos] == '-')) p->pos++;
        if (p->pos >= n || s[p->pos] < '0' || s[p->pos] > '9') return -1;
        while (p->pos < n && s[p->pos] >= '0' && s[p->pos] <= '9') p->pos++;
    }
    p->j->tok[t].end = (uint32_t)p->pos;
    p->j->tok[t].next = p->j->ntok;
    return t;
}

static int parse_value(parser *p);

/* two string tokens equal after unescaping? */
static int key_equal(const npf_json *j, int a, int b)
{
    char x[256], y[256];
    const npf_jtok *ta = &j->tok[a], *tb = &j->tok[b];
    if (!ta->escaped && !tb->escaped)
        return ta->end - ta->start == tb->end - tb->start
            && memcmp(j->s + ta->start, j->s + tb->start, ta->end - ta->start) == 0;
    if (npf_json_str(j, a, x, sizeof x) < 0 || npf_json_str(j, b, y, sizeof y) < 0)
        return 1;   /* oversized or NUL keys: treat as a clash, the message is rejected */
    return strcmp(x, y) == 0;
}

static int parse_container(parser *p, int is_obj)
{
    npf_json *j = p->j;
    int t = new_tok(p, is_obj ? NPF_JT_OBJECT : NPF_JT_ARRAY, p->pos);
    int count = 0;
    int keys[NPF_JSON_MAX_ARRAY];
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
            int k, i;
            if (p->pos >= j->len || j->s[p->pos] != '"')
                return -1;
            k = parse_string(p);
            if (k < 0)
                return -1;
            for (i = 0; i < count; i++)
                if (key_equal(j, keys[i], k))
                    return -1;
            keys[count] = k;
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
    j->tok[t].end = (uint32_t)p->pos;
    j->tok[t].next = j->ntok;
    return t;
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
    p->j->tok[t].end = (uint32_t)p->pos;
    p->j->tok[t].next = p->j->ntok;
    return t;
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

int npf_json_get(const npf_json *j, int obj, const char *key)
{
    int i, t;
    size_t kl = strlen(key);
    if (obj < 0 || obj >= j->ntok || j->tok[obj].type != NPF_JT_OBJECT)
        return -1;
    t = obj + 1;
    for (i = 0; i < j->tok[obj].size; i++) {
        const npf_jtok *k = &j->tok[t];
        int v = t + 1;
        if (!k->escaped) {
            if (k->end - k->start == kl && memcmp(j->s + k->start, key, kl) == 0)
                return v;
        } else {
            char buf[256];
            if (npf_json_str(j, t, buf, sizeof buf) >= 0 && strcmp(buf, key) == 0)
                return v;
        }
        t = j->tok[v].next;
    }
    return -1;
}

int npf_json_item(const npf_json *j, int arr, int i)
{
    int t, k;
    if (arr < 0 || arr >= j->ntok || j->tok[arr].type != NPF_JT_ARRAY || i < 0 || i >= j->tok[arr].size)
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
    const npf_jtok *k;
    size_t i, o = 0;
    if (t < 0 || t >= j->ntok || j->tok[t].type != NPF_JT_STRING || cap == 0)
        return -1;
    k = &j->tok[t];
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
            case 'u': {
                unsigned v = 0;
                int q;
                for (q = 0; q < 4; q++) v = (v << 4) | (unsigned)hexv(j->s[i + q]);
                i += 4;
                if (v >= 0xd800 && v <= 0xdbff) {
                    unsigned lo = 0;
                    for (q = 0; q < 4; q++) lo = (lo << 4) | (unsigned)hexv(j->s[i + 2 + q]);
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
    const npf_jtok *k;
    if (t < 0 || t >= j->ntok || j->tok[t].type != NPF_JT_STRING || j->tok[t].escaped)
        return 0;
    k = &j->tok[t];
    return k->end - k->start == l && memcmp(j->s + k->start, lit, l) == 0;
}

int npf_json_int(const npf_json *j, int t, int64_t min, int64_t max, int64_t *out)
{
    const npf_jtok *k;
    size_t i;
    int neg = 0;
    uint64_t v = 0;
    if (t < 0 || t >= j->ntok || j->tok[t].type != NPF_JT_NUMBER)
        return -1;
    k = &j->tok[t];
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
    if (t < 0 || t >= j->ntok)
        return -1;
    if (j->tok[t].type == NPF_JT_TRUE) { *out = 1; return 0; }
    if (j->tok[t].type == NPF_JT_FALSE) { *out = 0; return 0; }
    return -1;
}

int npf_json_b64(const npf_json *j, int t, uint8_t *out, size_t cap)
{
    if (t < 0 || t >= j->ntok || j->tok[t].type != NPF_JT_STRING || j->tok[t].escaped)
        return -1;
    return npf_b64url_decode(j->s + j->tok[t].start, j->tok[t].end - j->tok[t].start, out, cap);
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

/* ---- writer ---- */

static void put(npf_jw *w, const char *s, size_t n)
{
    if (w->err || w->len + n + 1 > w->cap) {
        w->err = 1;
        return;
    }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
}

static void sep(npf_jw *w)
{
    if (w->after_key) {
        w->after_key = 0;
        return;
    }
    if (w->depth > 0) {
        if (!w->first[w->depth])
            put(w, ",", 1);
        w->first[w->depth] = 0;
    }
}

void npf_jw_init(npf_jw *w, char *buf, size_t cap)
{
    memset(w, 0, sizeof *w);
    w->buf = buf;
    w->cap = cap;
}

static void open_c(npf_jw *w, char c)
{
    sep(w);
    put(w, &c, 1);
    if (w->depth >= NPF_JSON_MAX_DEPTH) {
        w->err = 1;
        return;
    }
    w->depth++;
    w->first[w->depth] = 1;
    w->kind[w->depth] = (uint8_t)c;
}

void npf_jw_obj(npf_jw *w) { open_c(w, '{'); }
void npf_jw_arr(npf_jw *w) { open_c(w, '['); }

void npf_jw_end(npf_jw *w)
{
    if (w->depth <= 0 || w->after_key) {
        w->err = 1;
        return;
    }
    put(w, w->kind[w->depth] == '[' ? "]" : "}", 1);
    w->depth--;
}

static void put_str(npf_jw *w, const char *v, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    put(w, "\"", 1);
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)v[i];
        if (c == '"' || c == '\\') {
            char e[2] = {'\\', (char)c};
            put(w, e, 2);
        } else if (c < 0x20) {
            char e[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
            put(w, e, 6);
        } else {
            put(w, (const char *)&v[i], 1);
        }
    }
    put(w, "\"", 1);
}

void npf_jw_key(npf_jw *w, const char *k)
{
    if (w->depth <= 0 || w->kind[w->depth] != '{' || w->after_key) {
        w->err = 1;
        return;
    }
    sep(w);
    put_str(w, k, strlen(k));
    put(w, ":", 1);
    w->after_key = 1;
}

void npf_jw_strn(npf_jw *w, const char *v, size_t n)
{
    sep(w);
    put_str(w, v, n);
}

void npf_jw_str(npf_jw *w, const char *v)
{
    npf_jw_strn(w, v, strlen(v));
}

void npf_jw_raw(npf_jw *w, const char *json, size_t n)
{
    sep(w);
    put(w, json, n);
}

void npf_jw_int(npf_jw *w, int64_t v)
{
    char b[24];
    int i = 23;
    uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    b[i] = 0;
    do {
        b[--i] = (char)('0' + u % 10);
        u /= 10;
    } while (u);
    if (v < 0)
        b[--i] = '-';
    npf_jw_raw(w, b + i, (size_t)(23 - i));
}

void npf_jw_bool(npf_jw *w, int v) { npf_jw_raw(w, v ? "true" : "false", v ? 4 : 5); }
void npf_jw_null(npf_jw *w) { npf_jw_raw(w, "null", 4); }

void npf_jw_b64(npf_jw *w, const uint8_t *v, size_t n)
{
    size_t need = NPF_B64_LEN(n) + 2;
    if (w->err || w->len + need + 2 > w->cap) {
        w->err = 1;
        return;
    }
    sep(w);
    w->buf[w->len++] = '"';
    w->len += npf_b64url_encode(v, n, w->buf + w->len);
    w->buf[w->len++] = '"';
}

void npf_jw_kstr(npf_jw *w, const char *k, const char *v) { npf_jw_key(w, k); npf_jw_str(w, v); }
void npf_jw_kint(npf_jw *w, const char *k, int64_t v) { npf_jw_key(w, k); npf_jw_int(w, v); }
void npf_jw_kbool(npf_jw *w, const char *k, int v) { npf_jw_key(w, k); npf_jw_bool(w, v); }
void npf_jw_kb64(npf_jw *w, const char *k, const uint8_t *v, size_t n) { npf_jw_key(w, k); npf_jw_b64(w, v, n); }

int npf_jw_finish(npf_jw *w)
{
    if (w->err || w->depth != 0 || w->len >= w->cap)
        return -1;
    w->buf[w->len] = 0;
    return (int)w->len;
}
