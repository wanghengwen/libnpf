/* Built without UDP signaling (NPF_SIG_UDP=OFF): WebSocket only */
#include "npf/sig.h"

npf_sig *npf_sig_open_udp(npf_loop *loop, npf_sig_send_fn send, const struct sockaddr_in *server,
                          const uint8_t server_pub[32], const npf_identity *id, npf_sig_cookie *cookie,
                          const npf_sig_cbs *cbs, void *arg)
{
    (void)loop, (void)send, (void)server, (void)server_pub, (void)id, (void)cookie, (void)cbs, (void)arg;
    return NULL;
}
