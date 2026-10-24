/* JSON parser / writer edge cases (signaling.md "JSON 与 C 解析约束"). */
#include <stdio.h>
#include <string.h>

#include "npf/json.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

static npf_jtok tok[256];

static int parse(const char *s, npf_json *j)
{
    return npf_json_parse(j, s, strlen(s), tok, 256);
}

static void test_parse(void)
{
    npf_json j;
    char buf[64];
    int64_t v;
    int b;
    CHECK(parse("{\"v\":1,\"type\":\"call\",\"data\":{\"n\":[1,2,3],\"ok\":true,\"x\":null}}", &j) == 0, "basic");
    CHECK(npf_json_get_int(&j, 0, "v", 0, 10, &v) == 0 && v == 1, "int");
    CHECK(npf_json_eq(&j, npf_json_get(&j, 0, "type"), "call"), "eq");
    {
        int d = npf_json_get(&j, 0, "data"), a = npf_json_get(&j, d, "n");
        CHECK(j.tok[a].size == 3 && npf_json_int(&j, npf_json_item(&j, a, 2), 0, 9, &v) == 0 && v == 3, "array");
        CHECK(npf_json_bool(&j, npf_json_get(&j, d, "ok"), &b) == 0 && b == 1, "bool");
        CHECK(npf_json_get(&j, d, "missing") < 0, "missing key");
    }
    /* duplicate keys, also after unescaping */
    CHECK(parse("{\"a\":1,\"a\":2}", &j) < 0, "duplicate key");
    CHECK(parse("{\"a\":1,\"\\u0061\":2}", &j) < 0, "duplicate key after unescape");
    CHECK(parse("{\"x\":{\"b\":1},\"\\u0078\":2}", &j) < 0, "duplicate key after a nested value");
    CHECK(parse("{\"a\":[1,{\"a\":2}],\"b\":3}", &j) == 0, "same key at another level is fine");
    {   /* many escaped keys (the token array's 256 allow 120): each unescaped once */
        static char big[8192];
        int n = 0, k;
        for (k = 0; k < 120; k++)
            n += snprintf(big + n, sizeof big - (size_t)n, "%s\"\\u006b%03d\":%d", k ? "," : "{", k, k);
        snprintf(big + n, sizeof big - (size_t)n, "}");
        CHECK(parse(big, &j) == 0, "120 distinct escaped keys");
        snprintf(big + n, sizeof big - (size_t)n, ",\"k100\":1}");
        CHECK(parse(big, &j) < 0, "a plain key equal to an escaped one");
    }
    /* escapes and UTF-8 */
    CHECK(parse("{\"s\":\"\\u4e2d\\ud83d\\ude00\\n\"}", &j) == 0
          && npf_json_get_str(&j, 0, "s", buf, sizeof buf) == 8 && memcmp(buf, "\xe4\xb8\xad\xf0\x9f\x98\x80\n", 8) == 0,
          "escape and surrogate pair");
    CHECK(parse("{\"s\":\"\\ud83d\"}", &j) < 0, "lone high surrogate");
    CHECK(parse("{\"s\":\"\\u0000\"}", &j) == 0 && npf_json_get_str(&j, 0, "s", buf, sizeof buf) < 0,
          "embedded NUL refused for C strings");
    CHECK(parse("{\"s\":\"\xc3\x28\"}", &j) < 0, "invalid UTF-8");
    CHECK(parse("{\"s\":\"\xed\xa0\x80\"}", &j) < 0, "UTF-8 surrogate");
    CHECK(parse("{\"s\":\"a\tb\"}", &j) < 0, "raw control character");
    /* numbers */
    CHECK(parse("{\"n\":1.5}", &j) == 0 && npf_json_get_int(&j, 0, "n", 0, 9, &v) < 0, "float is not an int");
    CHECK(parse("{\"n\":01}", &j) < 0, "leading zero");
    CHECK(parse("{\"n\":99999999999999999999}", &j) == 0 && npf_json_get_int(&j, 0, "n", 0, INT64_MAX, &v) < 0,
          "int overflow");
    CHECK(parse("{\"n\":-9223372036854775808}", &j) == 0 && npf_json_get_int(&j, 0, "n", INT64_MIN, 0, &v) == 0
          && v == INT64_MIN, "int64 min");
    /* structure */
    CHECK(parse("{\"a\":[[[[[[1]]]]]]}", &j) < 0, "depth > 6");
    CHECK(parse("{\"a\":[[[[1]]]]}", &j) == 0, "depth 5");
    CHECK(parse("{\"a\":1} x", &j) < 0, "trailing data");
    CHECK(parse("{\"a\":1,}", &j) < 0, "trailing comma");
    CHECK(parse("{\"a\" 1}", &j) < 0, "missing colon");
    CHECK(parse("{\"a\":tru}", &j) < 0, "bad literal");
    CHECK(parse("{\"a\":\"x", &j) < 0, "truncated");
    CHECK(parse("{\"b\":\"_-8\"}", &j) == 0, "base64 string");
    {
        uint8_t out[8];
        CHECK(parse("{\"b\":\"-_8BAgM\"}", &j) == 0 && npf_json_get_b64(&j, 0, "b", out, sizeof out) == 5,
              "base64url field");
    }
}

static void test_writer(void)
{
    char buf[256];
    npf_jw w;
    npf_json j;
    char s[64];
    npf_jw_init(&w, buf, sizeof buf);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "q", "a\"b\\c\n");
    npf_jw_kint(&w, "n", -42);
    npf_jw_key(&w, "arr");
    npf_jw_arr(&w);
    npf_jw_int(&w, 1);
    npf_jw_obj(&w);
    npf_jw_kbool(&w, "t", 1);
    npf_jw_end(&w);
    npf_jw_null(&w);
    npf_jw_end(&w);
    npf_jw_end(&w);
    CHECK(npf_jw_finish(&w) > 0, "writer finish");
    CHECK(strcmp(buf, "{\"q\":\"a\\\"b\\\\c\\u000a\",\"n\":-42,\"arr\":[1,{\"t\":true},null]}") == 0, "writer output %s", buf);
    CHECK(parse(buf, &j) == 0 && npf_json_get_str(&j, 0, "q", s, sizeof s) == 6 && strcmp(s, "a\"b\\c\n") == 0,
          "writer round trip");
    npf_jw_init(&w, buf, 8);
    npf_jw_obj(&w);
    npf_jw_kstr(&w, "long", "value");
    npf_jw_end(&w);
    CHECK(npf_jw_finish(&w) < 0, "writer overflow detected");
    npf_jw_init(&w, buf, sizeof buf);
    npf_jw_obj(&w);
    npf_jw_kint(&w, "a", 1);
    CHECK(npf_jw_finish(&w) < 0, "unclosed object detected");
}

int test_json(void)
{
    test_parse();
    test_writer();
    return fails;
}
