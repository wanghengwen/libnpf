/* Test hooks (npf/testhooks.h) */
#include "npf/sys.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/log.h"
#include "npf/testhooks.h"

void npf_th_read(npf_test_hooks *t)
{
    static const struct { const char *name; size_t off; int num; } sw[] = {
#define TH_N(f, name) {name, offsetof(npf_test_hooks, f), 1},
#define TH_S(f, name) {name, offsetof(npf_test_hooks, f), 0},
        NPF_TEST_HOOKS(TH_N, TH_S)
#undef TH_N
#undef TH_S
    };
    char on[512] = "";
    size_t i, k = 0;
    memset(t, 0, sizeof *t);
    for (i = 0; i < sizeof sw / sizeof sw[0]; i++) {
        const char *v = getenv(sw[i].name);
        void *p = (char *)t + sw[i].off;
        if (!v || !*v || (sw[i].num && strtoll(v, NULL, 10) <= 0))
            continue;                   /* off */
        if (sw[i].num)
            *(int64_t *)p = strtoll(v, NULL, 10);
        else
            *(const char **)p = v;
        if (k < sizeof on)
            k += (size_t)snprintf(on + k, sizeof on - k, " %s=%s", sw[i].name, v);
    }
    if (k)
        npf_logw("test switches on:%s", on);
}
