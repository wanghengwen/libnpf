/* Fixed-format parsers replacing scanf: cursor/buffer bounds, HTTP status,
 * route/MAC fields, HOST:PORT. */
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "npf/text.h"
#include "test.h"


int test_text(void)
{
    const char *p, *start;
    char word[8], num[80];
    unsigned char mac[6];
    unsigned long hex;
    int n, m;
    size_t i;

    p = " \talpha beta";
    EXPECT(npf_text_word(&p, word, sizeof word) == 0 && !strcmp(word, "alpha") && !strcmp(p, " beta"));
    EXPECT(npf_text_word(&p, word, sizeof word) == 0 && !strcmp(word, "beta") && !*p);
    EXPECT(npf_text_word(&p, word, sizeof word) < 0);
    start = p = "12345678 next";
    EXPECT(npf_text_word(&p, word, sizeof word) < 0 && p == start);
    EXPECT(npf_text_word(&p, word, 0) < 0 && p == start);
    p = "  +25,500";
    EXPECT(npf_text_int(&p, &n) == 0 && n == 25 && *p++ == ',' && npf_text_int(&p, &m) == 0 && m == 500 && !*p);
    snprintf(num, sizeof num, "%d", INT_MIN); p = num;
    EXPECT(npf_text_int(&p, &n) == 0 && n == INT_MIN && !*p);
    snprintf(num, sizeof num, "%d", INT_MAX); p = num;
    EXPECT(npf_text_int(&p, &n) == 0 && n == INT_MAX && !*p);
    snprintf(num, sizeof num, "%llu", (unsigned long long)INT_MAX + 1); start = p = num;
    EXPECT(npf_text_int(&p, &n) < 0 && p == start);
    start = p = " +no";
    EXPECT(npf_text_int(&p, &n) < 0 && p == start);

    p = "eth0\t00000000\t0101A8C0\t0003\t0";
    EXPECT(npf_text_word(&p, word, sizeof word) == 0 && !strcmp(word, "eth0"));
    EXPECT(npf_text_hex(&p, &hex) == 0 && hex == 0);
    EXPECT(npf_text_hex(&p, &hex) == 0 && hex == 0x0101a8c0UL);
    EXPECT(npf_text_hex(&p, &hex) == 0 && hex == 3);
    snprintf(num, sizeof num, "%lx", ULONG_MAX); p = num;
    EXPECT(npf_text_hex(&p, &hex) == 0 && hex == ULONG_MAX && !*p);
    strcat(num, "0"); start = p = num;
    EXPECT(npf_text_hex(&p, &hex) < 0 && p == start);
    start = p = "-1";
    EXPECT(npf_text_hex(&p, &hex) < 0 && p == start);
    EXPECT(npf_text_mac("01:23:45:67:89:aB", mac) == 0 && !memcmp(mac, "\x01\x23\x45\x67\x89\xab", 6));
    EXPECT(npf_text_mac("01:23:45:67:89", mac) < 0);
    EXPECT(npf_text_mac("01:23:45:67:89:100", mac) < 0);
    EXPECT(npf_text_mac("01:23:45:67:89:ab:cd", mac) < 0);

    {   /* HOST:PORT, [V6]:PORT: digits only, no leading zero, 0..65535, a host that fits */
        static const char *const bad[] = {"h", "h:", ":80", "[]:80", "[::1]80", "[::1:80", "h:+80", "h: 80", "h:080",
                                          "h:00", "h:65536", "h:99999999999", "h:80x", "toolonghost:1"};
        char h[8];
        uint16_t port;
        EXPECT(npf_hostport("a.b:65535", h, sizeof h, &port) == 0 && !strcmp(h, "a.b") && port == 65535);
        EXPECT(npf_hostport("[::1]:0", h, sizeof h, &port) == 0 && !strcmp(h, "::1") && port == 0);
        EXPECT(npf_hostport("::1:5", h, sizeof h, &port) == 0 && !strcmp(h, "::1") && port == 5);
        for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
            EXPECT(npf_hostport(bad[i], h, sizeof h, &port) < 0);
    }

    EXPECT(npf_http_status("HTTP/1.1 200 OK\r\n") == 200);
    EXPECT(npf_http_status("HTTP/1.0 404\r\n") == 404);
    EXPECT(npf_http_status("HTTP/1.1 2000 OK\r\n") < 0);
    EXPECT(npf_http_status("HTTP/1.x 200 OK\r\n") < 0);
    EXPECT(npf_http_status("HTTP/1.1 +200 OK\r\n") < 0);
    EXPECT(npf_http_status("HTTP/1.1 20x OK\r\n") < 0);
    for (i = 0; i <= 12; i++) {
        memcpy(num, "HTTP/1.1 200 OK", i); num[i] = 0;
        EXPECT(npf_http_status(num) < 0);
    }

    return fails;
}
