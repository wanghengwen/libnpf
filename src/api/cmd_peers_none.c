/* libnpf without sessions of its own (NPF_PEERS=OFF, a device build): the
 * commands of cmd_peers.c say they are not built in. */
#include "npf/sys.h"
#include "npf_int.h"

static int not_built(npf_out *o)
{
    npf_out_printf(o, "sessions to other nodes are not built into this npf (NPF_PEERS=OFF)\n");
    return 2;
}

int npf_cmd_peer_add(npf_t *c, int argc, char **argv, int flags, npf_out *o)
{
    (void)c, (void)argc, (void)argv, (void)flags;
    return not_built(o);
}

int npf_cmd_peer_remove(npf_t *c, const char *name, int unsave, npf_out *o)
{
    (void)c, (void)name, (void)unsave;
    return not_built(o);
}

int npf_cmd_forward(npf_t *c, int argc, char **argv, npf_out *o)
{
    (void)c, (void)argc, (void)argv;
    return not_built(o);
}

int npf_cmd_node(npf_t *c, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o)
{
    (void)c, (void)argc, (void)argv, (void)cb, (void)user;
    return not_built(o);
}
