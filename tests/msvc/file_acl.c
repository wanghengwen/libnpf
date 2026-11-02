/* A secret's check on Windows (scripts/msvc-check.sh): npf_file_too_open
 * lets SYSTEM, the Administrators, the file's owner and the user this
 * process runs as read it, no one else; npf_file_not_admins (a service's
 * files) stays stricter: the user's own entry is someone else's there.
 * The profile directory is the case of an elevated user's file: owned by
 * SYSTEM (an elevated user's by the Administrators), with an entry for the
 * user. 0: passed. */
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include "npf/sys.h"

static int fails;

static void check(int ok, const char *what)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    fails += !ok;
}

/* the owner of path is this process's user */
static int owned_by_me(const char *path)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    union {
        TOKEN_USER u;
        BYTE       b[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } t;
    HANDLE h;
    DWORD n;
    int r = 0;
    if (GetNamedSecurityInfoA(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, NULL, NULL, NULL, &sd)
        != ERROR_SUCCESS)
        return -1;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h)) {
        r = GetTokenInformation(h, TokenUser, &t, sizeof t, &n) && EqualSid(owner, t.u.User.Sid);
        CloseHandle(h);
    }
    LocalFree(sd);
    return r;
}

/* path's DACL from SDDL, protected */
static int set_dacl(const char *path, const char *sddl)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD r;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &sd, NULL))
        return -1;
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    r = SetNamedSecurityInfoA((char *)path, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);
    LocalFree(sd);
    return r == ERROR_SUCCESS ? 0 : -1;
}

int main(void)
{
    char dir[MAX_PATH], path[MAX_PATH + 16];
    const char *prof = getenv("USERPROFILE");
    HANDLE f;
    DWORD n;
    if (!GetTempPathA(sizeof dir, dir))
        return printf("FAIL no temp directory\n"), 1;
    snprintf(path, sizeof path, "%snpf-file-acl-%lu", dir, (unsigned long)GetCurrentProcessId());
    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE || !WriteFile(f, "secret\n", 7, &n, NULL))
        return printf("FAIL cannot write %s\n", path), 1;
    CloseHandle(f);

    check(npf_file_private(path) == 0 && !npf_file_too_open(path), "SYSTEM, the Administrators, the owner: private");
    check(set_dacl(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;BU)") == 0 && npf_file_too_open(path),
          "and the Users reading it: too open");
    check(set_dacl(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FX;;;BU)") == 0 && !npf_file_too_open(path),
          "the Users only executing it: private");
    check(set_dacl(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;IO;FR;;;BU)") == 0 && !npf_file_too_open(path),
          "an entry only for children: private");
    check(npf_file_not_admins(path) != NULL, "not the Administrators' alone (a service's check): the owner a user");
    set_dacl(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)");
    DeleteFileA(path);

    /* an entry for this user in a file another owns (an elevated user's own
     * file is the Administrators'): not someone else's */
    if (prof && owned_by_me(prof) == 0) {
        check(!npf_file_too_open(prof), "the profile directory (SYSTEM's, the user's entry in it): private");
        check(npf_file_not_admins(prof) != NULL, "but not the Administrators' alone: the user may change it");
    } else {
        printf("SKIP the profile directory is this user's own: the other-owner case not tested\n");
    }
    return fails ? 1 : 0;
}
