/* DNS TXT query and answers (npf/dns.h). */
#include <stdlib.h>
#include <string.h>

#include "npf/dns.h"

int npf_dns_txt_query(const char *name, uint16_t id, uint8_t *out, size_t cap)
{
    size_t o = 12;
    const char *p = name;
    if (cap < 12 + strlen(name) + 2 + 4)
        return -1;
    memset(out, 0, 12);
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = 0x01;                  /* RD */
    out[5] = 1;                     /* QDCOUNT */
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63)
            return -1;
        out[o++] = (uint8_t)l;
        memcpy(out + o, p, l);
        o += l;
        p += l + (dot ? 1 : 0);
    }
    out[o++] = 0;
    out[o++] = 0;
    out[o++] = 16;                  /* TXT */
    out[o++] = 0;
    out[o++] = 1;                   /* IN */
    return (int)o;
}

/* the offset after a (possibly compressed) name at off, or -1 */
static long skip_name(const uint8_t *m, size_t len, size_t off)
{
    int hops = 0;
    while (off < len) {
        uint8_t l = m[off];
        if (l == 0)
            return (long)off + 1;
        if ((l & 0xc0) == 0xc0)
            return off + 2 <= len ? (long)off + 2 : -1;   /* a pointer ends the name here */
        if (l & 0xc0 || ++hops > 128)
            return -1;
        off += 1 + (size_t)l;
    }
    return -1;
}

int npf_dns_txt_answers(const uint8_t *m, size_t len, npf_dns_txt_fn fn, void *arg)
{
    unsigned qd, an, i;
    long off = 12;
    int found = 0;
    if (len < 12 || !(m[2] & 0x80) || (m[3] & 0x0f) != 0)   /* a response without an error code */
        return -1;
    qd = (unsigned)(m[4] << 8 | m[5]);
    an = (unsigned)(m[6] << 8 | m[7]);
    for (i = 0; i < qd; i++) {
        if ((off = skip_name(m, len, (size_t)off)) < 0 || (size_t)off + 4 > len)
            return -1;
        off += 4;
    }
    for (i = 0; i < an; i++) {
        unsigned type, rdlen;
        if ((off = skip_name(m, len, (size_t)off)) < 0 || (size_t)off + 10 > len)
            return -1;
        type = (unsigned)(m[off] << 8 | m[off + 1]);
        rdlen = (unsigned)(m[off + 8] << 8 | m[off + 9]);
        off += 10;
        if ((size_t)off + rdlen > len)
            return -1;
        if (type == 16) {
            uint8_t *txt = malloc(rdlen ? rdlen : 1);
            size_t r = 0, w = 0;
            if (!txt)
                return -1;
            while (r < rdlen) {     /* <length><bytes>... joined */
                size_t l = m[off + (long)r];
                if (r + 1 + l > rdlen) {
                    free(txt);
                    return -1;
                }
                memcpy(txt + w, m + off + (long)r + 1, l);
                w += l;
                r += 1 + l;
            }
            fn(txt, w, arg);
            free(txt);
            found++;
        }
        off += rdlen;
    }
    return found;
}
