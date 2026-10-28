/* The node's spare allocation on the relay of its server (home-binding.md
 * v0.5): home.c binds it from the main socket (relay_bind.c) and answers the
 * relay's keepalive pings; the relay learns the interval itself; a call
 * takes it bound (node_home_adopt). */
#ifndef NPF_HOME_H
#define NPF_HOME_H

#include "relay_bind.h"

/* after welcome: home_open (a spare, or the one held resumed) when it may */
void node_home_login(npf_node *n);
/* the signaling connection went: the spare stays (U6) */
void node_home_sig_lost(npf_node *n);
/* the network may have changed, the main socket was opened again: bind again at once (the relay learns anew) */
void node_home_net_change(npf_node *n);
/* UDP works (a call's allocation bound, a NAT probe answered): a spare
 * backing off asks the platform at once (resume, or a new one) and binds */
void node_home_udp_ok(npf_node *n);
/* shutting down: home_close (best effort), no more keepalives */
void node_home_close(npf_node *n);
/* stopping: home_close if not yet, everything freed */
void node_home_stop(npf_node *n);
/* a datagram on the main socket: 1 when it was the spare's */
int  node_home_input(npf_node *n, int fd, const uint8_t *buf, size_t len, const struct sockaddr_storage *from);
/* the event relay_spare: another spare (the last one taken by a call, or rotated) */
void node_home_spare(npf_node *n, const npf_json *j, int d);
/* a call's allocation id: 1 when it is the spare, its binding then moved
 * into dst (bound already, or being bound) and the spare no longer here */
int  node_home_adopt(npf_node *n, const uint8_t id[8], relay_c *dst);

#endif
