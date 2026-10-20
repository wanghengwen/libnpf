/* Internal interfaces between the node modules (node.c, nat.c, call.c). */
#ifndef NPF_NODE_INTERNAL_H
#define NPF_NODE_INTERNAL_H

#include "npf/node.h"

/* node.c */
/* a signed list from the login, a push or an external channel (via): 1 when adopted */
int  node_server_list_update(npf_node *n, const uint8_t *blob, size_t len, const char *via);
const uint8_t *node_day_key(const npf_node *n, const npf_daykey keys[2]);
void node_apply_keys(npf_node *n, const npf_json *j, int d);

/* nat.c */
void node_nat_refresh(npf_node *n);
/* something seems lost (a call of ours timed out): ask the server with a ping;
 * no answer in time and the signaling is made again */
void node_sig_probe(npf_node *n);
/* node.c: connect again now (a new server list arrived) */
void node_reconnect_now(npf_node *n);

/* sources.c: the server list's external channels */
void node_sources_check(npf_node *n);   /* at each failed attempt: time for a round? */
void node_sources_stop(npf_node *n);
/* nodemap.c: the router's port mapping */
void node_portmap_start(npf_node *n);
void node_portmap_stop(npf_node *n);
/* the main socket has another port: the old lease is left to expire, a new one is asked for */
void node_portmap_restart(npf_node *n);
int  node_portmap_cand(const npf_node *n, struct sockaddr_storage *out);
/* nat.c: candidates again (a port mapping came or went) */
void node_nat_regather(npf_node *n);
/* at login: probe (on the loop); hooks.on_login at once with a profile from
 * before, else once the first one is measured */
void node_nat_login(npf_node *n);

/* call.c */
void node_dispatch(npf_node *n, const char *type, const npf_json *j, int d);
void node_sig_lost(npf_node *n);
/* returns 1 when the datagram belonged to a call */
int  node_udp_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
void node_calls_free(npf_node *n);


#endif
