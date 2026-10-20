/* DNS TXT query and answers (npf/dns.h): the server list's seed over DoH. */
#include <stdio.h>
#include <string.h>

#include "npf/dns.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static char got[2][600];
static int ngot;

static void on_txt(const uint8_t *t, size_t n, void *arg)
{
    (void)arg;
    if (ngot < 2 && n < sizeof got[0]) {
        memcpy(got[ngot], t, n);
        got[ngot][n] = 0;
    }
    ngot++;
}

int test_dns(void)
{
    uint8_t q[300], r[1200];
    int ql = npf_dns_txt_query("_n.example.com", 0x1234, q, sizeof q), i;
    size_t o;
    static const uint8_t want[] = {0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, '_', 'n', 7, 'e', 'x', 'a', 'm',
                                   'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 16, 0, 1};
    CHECK(ql == (int)sizeof want && memcmp(q, want, sizeof want) == 0, "query bytes");
    CHECK(npf_dns_txt_query("bad..name", 1, q, sizeof q) < 0, "an empty label is refused");

    /* a response: the question, a CNAME (skipped), then a TXT record of two
     * strings (300 bytes: more than one string) behind a compression pointer */
    memcpy(r, want, sizeof want);
    r[2] = 0x81;                    /* QR, RD */
    r[3] = 0x80;                    /* RA, rcode 0 */
    r[7] = 2;                       /* ANCOUNT */
    o = sizeof want;
    {   /* CNAME answer */
        static const uint8_t cn[] = {0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, 'x', 0xc0, 12};
        memcpy(r + o, cn, sizeof cn);
        o += sizeof cn;
    }
    {   /* TXT answer: 255 + 45 bytes */
        static const uint8_t th[] = {0xc0, 12, 0, 16, 0, 1, 0, 0, 0, 60};
        memcpy(r + o, th, sizeof th);
        o += sizeof th;
        r[o++] = (uint8_t)((302) >> 8);
        r[o++] = (uint8_t)(302 & 0xff);
        r[o++] = 255;
        for (i = 0; i < 255; i++)
            r[o++] = (uint8_t)('A' + i % 26);
        r[o++] = 45;
        for (i = 0; i < 45; i++)
            r[o++] = (uint8_t)('a' + i % 26);
    }
    ngot = 0;
    CHECK(npf_dns_txt_answers(r, o, on_txt, NULL) == 1 && ngot == 1 && strlen(got[0]) == 300 && got[0][0] == 'A'
              && got[0][255] == 'a',
          "TXT answer joined (%d answers)", ngot);
    /* malformed: truncated, a string past the record, an error code */
    CHECK(npf_dns_txt_answers(r, o - 10, on_txt, NULL) < 0, "truncated");
    r[sizeof want + 16 + 10 + 2] = 255;     /* the second string's length now runs past the record */
    r[sizeof want + 16 + 10 + 2 + 256] = 200;
    CHECK(npf_dns_txt_answers(r, o, on_txt, NULL) < 0, "a string past its record");
    r[3] = 0x83;                            /* NXDOMAIN */
    CHECK(npf_dns_txt_answers(r, o, on_txt, NULL) < 0, "an error code");
    return fails;
}
