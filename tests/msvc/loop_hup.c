/* The event loop on WSAPoll (scripts/msvc-check.sh): a socket watched for
 * writing only, whose peer sent its FIN with this side's send buffer full,
 * is not polled in a spin (WSAPoll reports its POLLHUP at once each time),
 * and its write event still comes once the peer reads. 0: passed. */
#include <winsock2.h>
#include <stdio.h>
#include "npf/loop.h"

static int calls, writable;

static void on_io(npf_loop *l, int fd, unsigned ev, void *arg)
{
    (void)l; (void)fd; (void)arg;
    calls++;
    if (ev & NPF_EV_WRITE)
        writable = 1;
}

int main(void)
{
    static char buf[65536];
    WSADATA w;
    SOCKET ls, a, b;
    struct sockaddr_in sa = {0};
    int len = sizeof sa, i, spin;
    u_long nb = 1;
    ULONGLONG t0;
    npf_loop *l;

    WSAStartup(MAKEWORD(2, 2), &w);
    ls = socket(AF_INET, SOCK_STREAM, 0);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ls, (struct sockaddr *)&sa, sizeof sa);
    listen(ls, 1);
    getsockname(ls, (struct sockaddr *)&sa, &len);
    a = socket(AF_INET, SOCK_STREAM, 0);
    connect(a, (struct sockaddr *)&sa, sizeof sa);
    b = accept(ls, NULL, NULL);
    ioctlsocket(a, FIONBIO, &nb);
    while (send(a, buf, sizeof buf, 0) > 0)
        ;
    shutdown(b, SD_SEND);
    Sleep(100);

    if (!(l = npf_loop_new()) || npf_loop_add(l, (int)a, NPF_EV_WRITE, on_io, NULL) < 0)
        return printf("FAIL loop\n"), 1;
    for (t0 = GetTickCount64(); GetTickCount64() - t0 < 1000;)
        npf_loop_once(l, 50);
    spin = calls;
    printf("%s a hang-up with a full send buffer: %d events in a second\n", spin <= 100 ? "PASS" : "FAIL", spin);
    ioctlsocket(b, FIONBIO, &nb);
    for (i = 0; i < 100 && !writable; i++) {    /* the peer reads: at most a second */
        while (recv(b, buf, sizeof buf, 0) > 0)
            ;
        npf_loop_once(l, 10);
    }
    printf("%s writable again once the peer read\n", writable ? "PASS" : "FAIL");
    npf_loop_free(l);
    return spin <= 100 && writable ? 0 : 1;
}
