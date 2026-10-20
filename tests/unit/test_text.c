/* Fixed-format parsers replacing scanf: cursor/buffer bounds, HTTP status,
 * route/MAC fields, and exact duration scaling including decimal exponents. */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "npf/text.h"

static int fails;
#define CHECK(x) do { if (!(x)) { fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

int test_text(void)
{
    const char *p, *start;
    char word[8], num[80];
    unsigned char mac[6];
    unsigned long hex;
    int n, m;
    size_t i;
    struct tm tm;
    static const struct { const char *s; int64_t seconds; } durations[] = {
        {"90s", 90}, {"30m", 1800}, {"8h", 28800}, {"3d", 259200}, {"1w", 604800},
        {"1.5h", 5400}, {"1.15h", 4140}, {".001h", 3}, {".1s", 0}, {"1.s", 1},
        {"0.999h", 3596}, {"1e2m", 6000}, {"1.25e+2s", 125}, {"125e-2s", 1},
        {"1e-9w", 0}, {"  +000.5h", 1800}, {"0001e2s", 100},
        {"1.999999999999999999999999999s", 1}, {"1e-2147483648s", 0}
    };
    static const char *bad[] = {
        "", "s", "0s", "0.0h", "-1h", "1", "1h ", "1 h", "1hh", "1.2.3h", "1eh", "1e h",
        "1e+h", "1e999999999999h", "infh", "nanh", "1e2147483647s", "999999999999999999999999w",
        "2026-10-16", "2026-10-16 12", "2026-10-16 12:", "2026-10-16 12:30tail",
        "2026-13-16 12:30", "2026-10-16 24:00"
    };

    p = " \talpha beta";
    CHECK(npf_text_word(&p, word, sizeof word) == 0 && !strcmp(word, "alpha") && !strcmp(p, " beta"));
    CHECK(npf_text_word(&p, word, sizeof word) == 0 && !strcmp(word, "beta") && !*p);
    CHECK(npf_text_word(&p, word, sizeof word) < 0);
    start = p = "12345678 next";
    CHECK(npf_text_word(&p, word, sizeof word) < 0 && p == start);
    CHECK(npf_text_word(&p, word, 0) < 0 && p == start);
    p = "  +25,500";
    CHECK(npf_text_int(&p, &n) == 0 && n == 25 && *p++ == ',' && npf_text_int(&p, &m) == 0 && m == 500 && !*p);
    snprintf(num, sizeof num, "%d", INT_MIN); p = num;
    CHECK(npf_text_int(&p, &n) == 0 && n == INT_MIN && !*p);
    snprintf(num, sizeof num, "%d", INT_MAX); p = num;
    CHECK(npf_text_int(&p, &n) == 0 && n == INT_MAX && !*p);
    snprintf(num, sizeof num, "%llu", (unsigned long long)INT_MAX + 1); start = p = num;
    CHECK(npf_text_int(&p, &n) < 0 && p == start);
    start = p = " +no";
    CHECK(npf_text_int(&p, &n) < 0 && p == start);

    p = "eth0\t00000000\t0101A8C0\t0003\t0";
    CHECK(npf_text_word(&p, word, sizeof word) == 0 && !strcmp(word, "eth0"));
    CHECK(npf_text_hex(&p, &hex) == 0 && hex == 0);
    CHECK(npf_text_hex(&p, &hex) == 0 && hex == 0x0101a8c0UL);
    CHECK(npf_text_hex(&p, &hex) == 0 && hex == 3);
    snprintf(num, sizeof num, "%lx", ULONG_MAX); p = num;
    CHECK(npf_text_hex(&p, &hex) == 0 && hex == ULONG_MAX && !*p);
    strcat(num, "0"); start = p = num;
    CHECK(npf_text_hex(&p, &hex) < 0 && p == start);
    start = p = "-1";
    CHECK(npf_text_hex(&p, &hex) < 0 && p == start);
    CHECK(npf_text_mac("01:23:45:67:89:aB", mac) == 0 && !memcmp(mac, "\x01\x23\x45\x67\x89\xab", 6));
    CHECK(npf_text_mac("01:23:45:67:89", mac) < 0);
    CHECK(npf_text_mac("01:23:45:67:89:100", mac) < 0);
    CHECK(npf_text_mac("01:23:45:67:89:ab:cd", mac) < 0);

    CHECK(npf_http_status("HTTP/1.1 200 OK\r\n") == 200);
    CHECK(npf_http_status("HTTP/1.0 404\r\n") == 404);
    CHECK(npf_http_status("HTTP/1.1 2000 OK\r\n") < 0);
    CHECK(npf_http_status("HTTP/1.x 200 OK\r\n") < 0);
    CHECK(npf_http_status("HTTP/1.1 +200 OK\r\n") < 0);
    CHECK(npf_http_status("HTTP/1.1 20x OK\r\n") < 0);
    for (i = 0; i <= 12; i++) {
        memcpy(num, "HTTP/1.1 200 OK", i); num[i] = 0;
        CHECK(npf_http_status(num) < 0);
    }

    for (i = 0; i < sizeof durations / sizeof durations[0]; i++)
        CHECK(npf_text_expiry(durations[i].s, 1000) == 1000 + durations[i].seconds);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECK(npf_text_expiry(bad[i], 1000) == -1);
    CHECK(npf_text_expiry("never", 1000) == 0);
    CHECK(npf_text_expiry("9223372036854775807s", 0) == INT64_MAX);
    CHECK(npf_text_expiry("9223372036854775807s", 1) == -1);
    CHECK(npf_text_expiry("1s", INT64_MAX - 1) == INT64_MAX);
    CHECK(npf_text_expiry("1s", INT64_MAX) == -1);
    memset(&tm, 0, sizeof tm);
    tm.tm_year = 126; tm.tm_mon = 9; tm.tm_mday = 16; tm.tm_hour = 12; tm.tm_min = 30; tm.tm_isdst = -1;
    CHECK(npf_text_expiry("2026-10-16 12:30", 1000) == (int64_t)mktime(&tm));
    CHECK(npf_text_expiry("2026-10-16T12:30", 1000) == (int64_t)mktime(&tm));
    return fails;
}
