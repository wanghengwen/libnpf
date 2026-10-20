#include "npf.h"                    /* npf_version is also public */
#include "npf/version.h"

/* the project's version (CMakeLists.txt project()): the only place it is written */
#ifndef NPF_VERSION_STR
#error "NPF_VERSION_STR: the version from CMakeLists.txt's project()"
#endif

const char *npf_version(void)
{
    return NPF_VERSION_STR;
}
