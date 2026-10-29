/* npf_version without the rest of npf.h, for code that does not use the
 * API: libnpf's own and npf's tools (npf-natprobe). The same function as
 * npf.h's: the version built in, a static string. */
#ifndef NPF_VERSION_H
#define NPF_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

const char *npf_version(void);

#ifdef __cplusplus
}
#endif

#endif /* NPF_VERSION_H */
