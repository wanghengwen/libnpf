/* JSON parser / writer edge cases (signaling.md "JSON 与 C 解析约束"). */
#include <stdio.h>
#include <stdlib.h>
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
    CHECK(parse("{\"\\u0074ype\":\"\\u0063all\"}", &j) == 0 && npf_json_eq(&j, npf_json_get(&j, 0, "type"), "call")
          && !npf_json_eq(&j, 1, "typ"), "an escaped key and value equal after unescaping");
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
    CHECK(parse("{\"a\":9223372036854775807,\"b\":9223372036854775808,\"c\":-9223372036854775809}", &j) == 0
          && npf_json_get_int(&j, 0, "a", 0, INT64_MAX, &v) == 0 && v == INT64_MAX
          && npf_json_get_int(&j, 0, "b", 0, INT64_MAX, &v) < 0 && npf_json_get_int(&j, 0, "c", INT64_MIN, 0, &v) < 0,
          "int64 bounds");
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

/* the messages we send: escaping, base64url, the size limit, a secret's growth */
static void test_writer(void)
{
    npf_out w = {0};
    npf_json j;
    char s[64];
    uint8_t b[5];
    int i;
    npf_out_jobj(&w);
    npf_out_kstr(&w, "q", "a\"b\\c\n\x01");
    npf_out_kint(&w, "n", -42);
    npf_out_kb64(&w, "b", (const uint8_t *)"\xfb\xff\x01\x02\x03", 5);
    npf_out_jkey(&w, "k\"");                   /* keys escaped too */
    npf_out_jarr(&w);
    npf_out_jint(&w, 1);
    npf_out_jobj(&w);
    npf_out_kbool(&w, "t", 1);
    npf_out_jend(&w);
    npf_out_jstr(&w, NULL);
    npf_out_jb64(&w, NULL, 0);
    npf_out_jend(&w);
    npf_out_jend(&w);
    CHECK(!w.failed && strcmp(w.p, "{\"q\":\"a\\\"b\\\\c\\n\\u0001\",\"n\":-42,\"b\":\"-_8BAgM\",\"k\\\"\":[1,{\"t\":true},"
                                   "null,\"\"]}") == 0, "writer output %s", w.p);
    CHECK(parse(w.p, &j) == 0 && npf_json_get_str(&j, 0, "q", s, sizeof s) == 7 && strcmp(s, "a\"b\\c\n\x01") == 0
          && npf_json_get_b64(&j, 0, "b", b, sizeof b) == 5 && b[0] == 0xfb, "writer round trip");
    npf_out_free(&w);
    npf_out_jend(&w);
    CHECK(w.failed, "an end with nothing open fails");
    npf_out_free(&w);
    w.max = 16;                                 /* at most 16 bytes: 16 fit, 17 do not */
    npf_out_jobj(&w);
    npf_out_kstr(&w, "long", "value");
    npf_out_jend(&w);
    CHECK(!w.failed && w.len == 16, "16 bytes within a limit of 16 (%d)", (int)w.len);
    npf_out_free(&w);
    CHECK(w.max == 16, "the limit stays after free");
    npf_out_jobj(&w);
    npf_out_kstr(&w, "long", "value!");
    npf_out_jend(&w);
    CHECK(w.failed, "17 bytes over a limit of 16");
    npf_out_kint(&w, "more", 1);
    CHECK(w.failed && w.len <= 16, "failed stays failed");
    npf_out_free(&w);
    w = (npf_out){.secret = 1};                 /* grows by copies, the old ones wiped */
    npf_out_jarr(&w);
    for (i = 0; i < 200; i++)
        npf_out_jstr(&w, "password");
    npf_out_jend(&w);
    CHECK(!w.failed && w.len == 2 + 200 * 10 + 199 && w.cap >= w.len + 1 && parse(w.p, &j) == 0, "a secret grown");
    npf_out_free(&w);
    CHECK(!w.p && w.secret, "a secret freed");
    {   /* base64url longer than the writer's 192-byte steps, in a secret */
        uint8_t in[500], out[500];
        for (i = 0; i < 500; i++)
            in[i] = (uint8_t)(i * 7);
        npf_out_jobj(&w);
        npf_out_kb64(&w, "k", in, sizeof in);
        npf_out_jend(&w);
        CHECK(!w.failed && parse(w.p, &j) == 0 && npf_json_get_b64(&j, 0, "k", out, sizeof out) == 500
              && memcmp(in, out, 500) == 0, "500 bytes of base64url");
        npf_out_free(&w);
    }
}

/* the writer: commas by themselves, text of one's own after a key */
static void test_out(void)
{
    npf_out o = {0};
    npf_json j;
    npf_out_jobj(&o);
    npf_out_kstr(&o, "s", "a\"b");
    npf_out_kstr(&o, "none", NULL);
    npf_out_jkey(&o, "raw");
    npf_out_printf(&o, "{\"x\":1}");          /* a writer of its own */
    npf_out_kint(&o, "n", -7);
    npf_out_jkey(&o, "arr");
    npf_out_jarr(&o);
    npf_out_jstr(&o, "i");
    npf_out_jraw(&o, "2");
    npf_out_jobj(&o);
    npf_out_kbool(&o, "t", 1);
    npf_out_jend(&o);
    npf_out_jend(&o);
    npf_out_kbool(&o, "f", 0);
    npf_out_jend(&o);
    CHECK(!o.failed && strcmp(o.p, "{\"s\":\"a\\\"b\",\"none\":null,\"raw\":{\"x\":1},\"n\":-7,"
                                  "\"arr\":[\"i\",2,{\"t\":true}],\"f\":false}") == 0, "out JSON %s", o.p);
    CHECK(parse(o.p, &j) == 0, "out JSON parses");
    npf_out_free(&o);
    npf_out_jarr(&o);
    npf_out_jend(&o);
    npf_out_printf(&o, " ");
    npf_out_jstr(&o, "top");                    /* the top level: as it is */
    npf_out_jstr(&o, "level");
    CHECK(o.p && strcmp(o.p, "[] \"top\"\"level\"") == 0, "out JSON at the top level: no commas");
    npf_out_free(&o);
}

/* our own big JSON: long arrays, tokens on the heap */
static void test_big(void)
{
    static char s[8192];
    npf_json j = {0};
    int n = 0, k, t;
    for (k = 0; k < 300; k++)
        n += snprintf(s + n, sizeof s - (size_t)n, "%s%d", k ? "," : "{\"a\":[", k);
    snprintf(s + n, sizeof s - (size_t)n, "],\"b\":true}");
    CHECK(parse(s, &j) < 0, "300 items: not in a message");
    CHECK(npf_json_parse_big(&j, s, strlen(s)) == 0 && (t = npf_json_get(&j, 0, "a")) >= 0 && j.tok[t].size == 300
          && s[j.tok[t].start] == '[' && s[j.tok[t].end - 1] == ']' && npf_json_get(&j, 0, "b") >= 0,
          "300 items in our own JSON");
    npf_json_free(&j);
    CHECK(!j.tok, "freed");
    for (n = 0, k = 0; k < 300; k++)
        n += snprintf(s + n, sizeof s - (size_t)n, "%s\"k%d\":1", k ? "," : "{", k);
    snprintf(s + n, sizeof s - (size_t)n, "}");
    CHECK(npf_json_parse_big(&j, s, strlen(s)) < 0 && !j.tok, "an object still at most 256 keys");
    npf_json_free(&j);
    CHECK(npf_json_parse_big(&j, "1", 1) == 0 && j.ntok == 1, "one token");
    npf_json_free(&j);
    CHECK(npf_json_parse_big(&j, "", 0) < 0, "empty");
    {
        char *huge = calloc(1, NPF_JSON_MAX_FILE + 2);
        CHECK(huge && (memset(huge, ' ', NPF_JSON_MAX_FILE + 1), huge[0] = '1', npf_json_parse_big(&j, huge, NPF_JSON_MAX_FILE + 1) < 0),
              "more than NPF_JSON_MAX_FILE");
        free(huge);
    }
}

int test_json(void)
{
    test_parse();
    test_big();
    test_writer();
    test_out();
    return fails;
}
