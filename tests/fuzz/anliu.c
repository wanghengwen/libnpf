/* Authenticated-peer fuzzing: feed mutated plaintext segments to the real
 * AnLiu parser. Ciphertext-only mutations almost always stop at the MAC. */
#include "../../third_party/anliu/anliu.c"
#include <stdio.h>

static uint32_t seed = 1;
static uint32_t random32(void)
{
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}
static int discard(char *p, int n, anl_t *w, void *arg)
{
    (void)p; (void)n; (void)w; (void)arg;
    return 0;
}
int main(int argc, char **argv)
{
    unsigned iterations = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 10000, it;
    char input[1400], output[65536];
    if (argc > 2) seed = (uint32_t)strtoul(argv[2], NULL, 10);
    if (!seed) seed = 1;
    for (it = 0; it < iterations; it++) {
        anl_config cfg;
        anl_stream_opt opt;
        anl_t *w;
        anl_stream *s;
        unsigned i, pass;
        anl_config_default(&cfg, ANL_ROLE_SERVER);
        cfg.mtu = sizeof input;
        cfg.default_rcv_wnd = 32;
        w = anl_create(123, &cfg, NULL);
        if (!w) return 2;
        anl_setoutput(w, discard);
        anl_update(w, 1000);
        anl_stream_opt_default(&opt, ANL_SEMI);
        opt.rcv_wnd = 32;
        opt.fec = 1;
        s = stream_create(w, 2, &opt);
        if (!s) { anl_release(w); return 2; }
        s->state = ANL_STREAM_OPEN;
        for (pass = 0; pass < 4; pass++) {
            anl_stream_t *rd[ANL_MAX_STREAMS];
            char *p = input;
            size_t n;
            int count, k;
            p = enc32(p, 123);
            p = enc8(p, (uint8_t)(ANL_VERSION << 6));
            p = enc16(p, 1000);
            p = enc32(p, pass);
            if ((it & 3) == 0) {
                /* A valid DATA or PARITY segment before mutation. */
                p = enc_sid(p, SEG_DATA, 2);
                p = enc8(p, F_HAS_FRAME | F_KEY);
                p = enc24(p, pass);
                p = enc16(p, (uint16_t)pass);
                p = enc_varint(p, 16);
                memset(p, 'x', 16); p += 16;
            } else if ((it & 3) == 1) {
                p = enc_sid(p, SEG_CTRL, 2);
                p = enc8(p, CTRL_PARITY);
                p = enc_varint(p, PARITY_HDR + 16);
                p = enc24(p, 0);
                p = enc8(p, 1); p = enc8(p, 1); p = enc8(p, 0);
                memset(p, 0, 16); p += 16;
            } else {
                unsigned payload = 1 + random32() % 300;
                for (i = 0; i < payload; i++) *p++ = (char)random32();
            }
            n = (size_t)(p - input);
            for (i = 0; i < random32() % 8; i++) {
                size_t pos = ANL_HDR_SIZE + random32() % (n - ANL_HDR_SIZE);
                input[pos] ^= (char)(1u << (random32() % 8));
            }
            if ((random32() & 7) == 0) n = random32() % (n + 1);
            (void)anl_input_plain(w, input, (long)n);
            count = anl_readable(w, rd, ANL_MAX_STREAMS);
            for (k = 0; k < count && k < ANL_MAX_STREAMS; k++) {
                if (rd[k]->mode == ANL_SEMI)
                    (void)anl_stream_recv_frame(rd[k], output, sizeof output, NULL);
                else
                    (void)anl_stream_recv(rd[k], output, sizeof output);
            }
            anl_update(w, 1010 + pass * 10);
        }
        anl_release(w);
    }
    printf("ok: %u AnLiu authenticated-peer cases\n", iterations);
    return 0;
}
