/* libnpf: the node command's list and settings: the nodes npf knows (those
 * of local.json, with their names and nicks, and the peers connected), a
 * name or a nick set. A module may list more (the account's devices on the
 * platform: npf_module.node_list) and pass a nick on (nick_set). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf_int.h"
#include "npf/module.h"
#include "npf/peers.h"

void npf_nodes_header(npf_out *o)
{
    npf_out_printf(o, "%-22s %-12s %-17s %-30s %s\n", "NODE", "NAME", "ACCOUNT", "HERE", "NICK");
}

void npf_nodes_line(npf_t *c, npf_out *o, const char *target, const npf_ldev *d, const char *acct)
{
    npf_peer *p = npf_peers_find(c->peers, target);
    char here[96] = "", st[80];
    size_t h = 0;
    if (c->has_number && npf_number_parse(target) == c->number)
        h += (size_t)snprintf(here + h, sizeof here - h, "this computer");
    else if (p && npf_peer_call(p) && npf_call_state(npf_peer_call(p)) == NPF_CALL_ESTABLISHED)
        h += (size_t)snprintf(here + h, sizeof here - h, "connected (%s)", npf_call_path_label(npf_peer_call(p)));
    else if (p)
        h += (size_t)snprintf(here + h, sizeof here - h, "%s", npf_peer_status(p, st, sizeof st));
    if ((d && d->save) || (p && npf_peer_tag(p) == PEER_FIXED))
        h += (size_t)snprintf(here + h, sizeof here - h, "%ssaved", h ? ", " : "");
    else if (p)
        h += (size_t)snprintf(here + h, sizeof here - h, ", this time");
    npf_out_printf(o, "%-22s %-12s %-17s %-30s %s\n", target, d && d->name[0] ? d->name : "-",
                   acct && *acct ? acct : "-", h ? here : "-", d ? d->nick : "");
}

int npf_nodes_local(npf_t *c, npf_out *o, int (*listed)(void *arg, const char *target), void *arg)
{
    npf_peer *p;
    int i, any = 0;
    for (i = 0; i < c->lc.ndev; i++) {
        const npf_ldev *d = &c->lc.dev[i];
        if ((listed && listed(arg, d->target)) || (!d->name[0] && !d->nick[0] && !d->save && !d->has_key))
            continue;
        npf_nodes_line(c, o, d->target, d, NULL);
        any = 1;
    }
    for (p = npf_peers_first(c->peers); p; p = npf_peer_next(p))     /* connected this time only (not kept) */
        if (!(listed && listed(arg, npf_peer_name(p))) && !npf_local_dev(&c->lc, npf_peer_name(p), 0)) {
            npf_nodes_line(c, o, npf_peer_name(p), NULL, NULL);
            any = 1;
        }
    return any;
}

int npf_nodes_set_nick(npf_t *c, const char *target, const char *nick, npf_out *o)
{
    npf_ldev *d;
    if (!npf_nick_valid(nick)) {
        npf_out_printf(o, "a nick is up to %d bytes of text without control characters\n", NPF_NICK_MAX);
        return 2;
    }
    if (!(d = npf_local_dev(&c->lc, target, 1))) {
        npf_out_printf(o, "too many devices in %s\n", c->local_path);
        return 1;
    }
    snprintf(d->nick, sizeof d->nick, "%s", nick);
    if (npf_local_save(&c->lc) < 0) {
        npf_out_printf(o, "cannot write %s\n", c->local_path);
        return 1;
    }
    npf_mods_nick_set(c, target, nick);     /* the platform's alias too (a module) */
    return 0;
}

/* node                                    the list (argv[0] the command)
 * node set TARGET [--name NAME] [--nick TEXT]   set (an empty value removes it) */
int npf_cmd_nodes(npf_t *c, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o)
{
    char tbuf[300], err[300];
    const char *target;
    int i, rc = 0, set = 0;
    if (argc < 2) {
        if (npf_mods_node_list(c, cb, user, o, &rc))
            return rc;
        npf_nodes_header(o);
        if (!npf_nodes_local(c, o, NULL, NULL))
            npf_out_printf(o, "(no nodes yet: npf node add NUMBER)\n");
        return 0;
    }
    target = npf_peers_resolve(c->peers, argv[1], tbuf, sizeof tbuf);
    if (!strchr(target, ':') && !npf_number_parse(target)) {
        npf_out_printf(o, "%s: not a device number, HOST:PORT or a name given before\n", argv[1]);
        return 1;
    }
    for (i = 2; i < argc; i += 2) {         /* option and value */
        if (i + 1 < argc && strcmp(argv[i], "--name") == 0) {
            if (npf_peers_name_set(c->peers, argv[i + 1], target, err, sizeof err) < 0) {
                npf_out_printf(o, "%s\n", err);
                return 2;
            }
            npf_out_printf(o, argv[i + 1][0] ? "%s: named %s\n" : "%s: name removed%s\n", target, argv[i + 1]);
        } else if (i + 1 < argc && strcmp(argv[i], "--nick") == 0) {
            if ((rc = npf_nodes_set_nick(c, target, argv[i + 1], o)) != 0)
                return rc;
            npf_out_printf(o, argv[i + 1][0] ? "%s: nick \"%s\"\n" : "%s: nick removed%s\n", target, argv[i + 1]);
        } else {
            npf_out_printf(o, "node set NUMBER|NAME [--name NAME] [--nick TEXT]\n");
            return 2;
        }
        set = 1;
    }
    if (!set) {                             /* one device: its line */
        npf_nodes_header(o);
        npf_nodes_line(c, o, target, npf_local_dev(&c->lc, target, 0), NULL);
    }
    return 0;
}
