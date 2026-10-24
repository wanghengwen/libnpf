#define _DEFAULT_SOURCE
#include "npf/sys.h"
#include <string.h>

#include "npf/bind.h"
#include "npf/platform.h"

static void st16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint16_t ld16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static void st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

size_t npf_rand_range(size_t lo, size_t hi)
{
    uint32_t r, span, limit;
    if (hi <= lo)
        return lo;
    span = (uint32_t)(hi - lo + 1);
    limit = UINT32_MAX - UINT32_MAX % span;     /* rejection sampling: no modulo bias */
    do {
        npf_random(&r, sizeof(r));
    } while (r >= limit);
    return lo + r % span;
}

int npf_pkt_seal(const npf_siv_keys *keys, int dir, int type, const uint8_t txid[NPF_TXID_SIZE],
                 uint32_t ts_ms, const uint8_t *body, size_t body_len, size_t wire_len, uint8_t *out)
{
    uint8_t *p = out + NPF_SIV_TAG_SIZE;
    size_t plen, used;
    if (wire_len > NPF_PKT_MAX || wire_len < NPF_SIV_TAG_SIZE + NPF_PKT_HDR_SIZE + body_len
        || body_len > 0xffff)
        return -1;
    plen = wire_len - NPF_SIV_TAG_SIZE;
    p[0] = (uint8_t)type;
    p[1] = 0;                                   /* flags */
    st16(p + 2, (uint16_t)body_len);
    memcpy(p + 4, txid, NPF_TXID_SIZE);
    st32(p + 16, ts_ms);
    if (body_len)
        memcpy(p + NPF_PKT_HDR_SIZE, body, body_len);
    used = NPF_PKT_HDR_SIZE + body_len;
    if (plen > used)
        memset(p + used, 0, plen - used);       /* padding: encrypted with the rest (SIV, the random
                                                 * txid in its IV): zeros look as random, no syscall */
    npf_siv_seal(keys, dir, out, plen);
    return (int)wire_len;
}

int npf_pkt_open(const npf_siv_keys *keys, int dir, const uint8_t *in, size_t len,
                 uint8_t *plain, npf_pkt *pkt)
{
    int plen;
    size_t blen;
    if (len > NPF_PKT_MAX)
        return -1;                  /* longer than any packet; plain holds NPF_PKT_MAX (it was decrypted
                                       into it before the tag was checked: a stack overflow, no key needed) */
    plen = npf_siv_open(keys, dir, in, len, plain);
    if (plen < NPF_PKT_HDR_SIZE)
        return -1;
    blen = ld16(plain + 2);
    if (NPF_PKT_HDR_SIZE + blen > (size_t)plen)
        return -1;
    pkt->type = plain[0];
    memcpy(pkt->txid, plain + 4, NPF_TXID_SIZE);
    pkt->ts_ms = ld32(plain + 16);
    pkt->body = plain + NPF_PKT_HDR_SIZE;
    pkt->body_len = blen;
    return 0;
}

int npf_bind_resp_parse(const npf_pkt *pkt, npf_bind_resp *resp)
{
    const uint8_t *b = pkt->body;
    size_t alen;
    int i;
    if (pkt->type != NPF_PKT_BIND_RESP || pkt->body_len < 1)
        return -1;
    resp->family = b[0];
    if (resp->family == 4)
        alen = 4;
    else if (resp->family == 6)
        alen = 16;
    else
        return -1;
    if (pkt->body_len < 1 + 2 + alen + 8)
        return -1;
    resp->port = ld16(b + 1);
    memset(resp->addr, 0, sizeof(resp->addr));
    memcpy(resp->addr, b + 3, alen);
    resp->srv_time_ms = 0;
    for (i = 7; i >= 0; i--)
        resp->srv_time_ms = (resp->srv_time_ms << 8) | b[3 + alen + i];
    return 0;
}

int npf_bind_query(int fd, const struct sockaddr_in *ep, const npf_siv_keys *keys,
                   const uint8_t *ticket, size_t ticket_len, int64_t offset_ms,
                   struct sockaddr_in *mapped, int timeout_ms)
{
    static const int send_at[] = { 0, 200, 600 };
    uint8_t txid[NPF_TXID_SIZE];
    int64_t start = npf_mono_ms();
    int sent = 0;
    struct pollfd pfd = { fd, POLLIN, 0 };

    npf_random(txid, sizeof(txid));
    for (;;) {
        int64_t now = npf_mono_ms(), due;
        if (now - start >= timeout_ms)
            return -1;
        while (sent < 3 && now - start >= send_at[sent]) {
            uint8_t wire[NPF_PKT_MAX];
            size_t len = npf_rand_range(NPF_BIND_REQ_MIN, NPF_BIND_REQ_MAX);
            int n = npf_pkt_seal(keys, NPF_DIR_REQ, NPF_PKT_BIND_REQ, txid,
                                 (uint32_t)(npf_unix_ms() + offset_ms), ticket, ticket_len, len, wire);
            if (n > 0)
                (void)npf_udp_send(fd, wire, (size_t)n, ep);
            sent++;
        }
        due = sent < 3 ? start + send_at[sent] : start + timeout_ms;
        if (poll(&pfd, 1, (int)(due > now ? due - now : 0)) <= 0)
            continue;
        {
            uint8_t buf[NPF_PKT_MAX], plain[NPF_PKT_MAX];
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t r = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            npf_pkt pkt;
            npf_bind_resp resp;
            if (r <= 0 || from.sin_addr.s_addr != ep->sin_addr.s_addr || from.sin_port != ep->sin_port)
                continue;
            if (npf_pkt_open(keys, NPF_DIR_RESP, buf, (size_t)r, plain, &pkt) < 0)
                continue;
            if (memcmp(pkt.txid, txid, NPF_TXID_SIZE) != 0 || npf_bind_resp_parse(&pkt, &resp) < 0 || resp.family != 4)
                continue;
            memset(mapped, 0, sizeof(*mapped));
            mapped->sin_family = AF_INET;
            memcpy(&mapped->sin_addr, resp.addr, 4);
            mapped->sin_port = htons(resp.port);
            return 0;
        }
    }
}
