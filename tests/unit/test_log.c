/* Log levels and the recent-lines buffer (npf/log.h). */
#include <stdio.h>
#include <string.h>

#include "npf/log.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (!(cond)) { fails++; fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
                   fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } \
} while (0)

int test_log(void)
{
    static char buf[20000];
    int old = npf_log_get_level(), i;
    CHECK(npf_log_level_parse("error") == NPF_LOG_ERROR && npf_log_level_parse("trace") == NPF_LOG_TRACE
          && npf_log_level_parse("info") == NPF_LOG_INFO, "level names");
    CHECK(npf_log_level_parse("verbose") < 0 && npf_log_level_parse("") < 0 && npf_log_level_parse(NULL) < 0,
          "unknown level names");
    CHECK(strcmp(npf_log_level_name(NPF_LOG_WARN), "warn") == 0, "level name");

    npf_log_set_level(NPF_LOG_WARN);
    CHECK(!npf_log_on(NPF_LOG_INFO) && npf_log_on(NPF_LOG_WARN) && npf_log_on(NPF_LOG_ERROR), "filter");
    npf_log("test-log: info line %d", 1);          /* filtered */
    npf_logw("test-log: warn line %d", 2);
    npf_logd("test-log: debug line %d", 3);         /* filtered */
    npf_log_set_level(NPF_LOG_DEBUG);
    npf_logd("test-log: debug line %d", 4);
    npf_log_recent(buf, sizeof buf);
    CHECK(!strstr(buf, "info line 1") && !strstr(buf, "debug line 3"), "filtered lines are not kept");
    CHECK(strstr(buf, "WARN  test-log: warn line 2\n") != NULL, "warn line with its level: %s", buf);
    CHECK(strstr(buf, "DEBUG test-log: debug line 4 (test_log.c:") != NULL, "debug line with the source");

    /* the buffer keeps the last lines, whole ones */
    npf_log_set_level(NPF_LOG_ERROR);
    for (i = 0; i < 400; i++)
        npf_loge("test-log: filler %03d .........................................................", i);
    {
        size_t n = npf_log_recent(buf, 1000);
        CHECK(n < 1000 && n > 0 && buf[n - 1] == '\n', "a short copy ends with a whole line");
        CHECK(buf[4] == '-' && strstr(buf, "filler 399") != NULL, "starts at a line, ends with the last: %.40s", buf);
    }
    npf_log_set_level(old);
    return fails;
}
