/* libnpf: the commands of the sessions this npf starts (NPF_PEERS; without
 * them cmd_peers_none.c): node add / del / state / wake (node and node set:
 * nodes.c), forward, and the peers of the library's interface
 * (npf_peer_add / npf_peer_remove, npf_forward_*). Saved peers and their
 * forwards go to local.json (npf/local.h). */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "npf/sys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "npf/platform.h"
#include "npf_int.h"
#include "npf/module.h"

/* a peer's port mappings, one per line, with their state */
static void mappings_text(const npf_peer *p, npf_out *o)
{
    int i;
    for (i = 0; i < npf_peer_nfwd(p); i++) {
        char opt, st[120];
        const char *spec;
        int perm;
        char src[32];
        if (!npf_peer_forward_info(p, i, &opt, &spec, &perm, st, sizeof st))
            continue;
        if (npf_peer_forward_ext(p, i))
            snprintf(src, sizeof src, "platform #%llu", (unsigned long long)npf_peer_forward_ext(p, i));
        else
            snprintf(src, sizeof src, "%s", perm ? "saved" : "temporary");
        npf_out_printf(o, "    %3d  -%c %-36s %-12s %s\n", npf_peer_forward_id(p, i), opt, spec, src, st);
    }
}

/* a peer for people: "dev (611631552)" when it has a name */
static const char *peer_full(const npf_peer *p, char *buf, size_t cap)
{
    if (npf_peer_label(p)[0])
        snprintf(buf, cap, "%s (%s)", npf_peer_label(p), npf_peer_name(p));
    else
        snprintf(buf, cap, "%s", npf_peer_name(p));
    return buf;
}

/* ---- peers ---- */

/* a peer saved in local.json: connected at every start with these forwards
 * (the pairing password is not kept: once paired, the key is pinned) */
static int save_peer(npf_t *c, const npf_peer *p, int argc, char **argv, int fwds)
{
    npf_ldev *d = npf_local_dev(&c->lc, npf_peer_name(p), 1);
    int i;
    if (!d)
        return -1;
    d->save = 1;
    npf_local_fwd_clear(d);
    d->psk_file[0] = d->psk[0] = 0;
    for (i = 1; i + 1 < argc; i++) {
        if (npf_fwd_opt(argv[i])) {
            if (fwds)
                npf_local_fwd_add(d, argv[i], argv[i + 1]);
        } else if (strcmp(argv[i], "--psk-file") == 0)
            snprintf(d->psk_file, sizeof d->psk_file, "%s", argv[i + 1]);
        else if (strcmp(argv[i], "--psk") == 0)
            snprintf(d->psk, sizeof d->psk, "%s", argv[i + 1]);
        else
            continue;
        i++;
    }
    npf_mods_fwds_saved(c, d);
    return npf_local_save(&c->lc);
}

/* add the peers described by words (groups separated by "+"); 0 or exit
 * code. On an error the groups before it stay added (and start) */
static int forward_one(npf_t *c, npf_peer *p, int add, const char *opt, const char *spec, int perm, npf_out *o);

int npf_cmd_peer_add(npf_t *c, int argc, char **argv, int flags, npf_out *o)
{
    int save = flags & NPF_PEER_SAVE;
    int start = 0, i, added = 0, seen = 0, rc = 0, unsaved = 0;
    for (i = 0; i <= argc && !rc; i++) {
        char err[300], line[1024];
        npf_peer *p;
        int k;
        if (i < argc && strcmp(argv[i], "+") != 0)
            continue;
        if (i == start) {
            start = i + 1;
            continue;
        }
        for (k = start; save && k < i; k++)
            if (!npf_conf_value_ok(argv[k])) {
                npf_out_printf(o, "%s: a saved peer's words must be one line without '#'\n", argv[start]);
                rc = 2;
            }
        if (rc)
            break;
        seen++;
        if (c->has_number && npf_number_parse(npf_peers_resolve(c->peers, argv[start], line, sizeof line)) == c->number) {
            npf_out_printf(o, "%llu is this computer's own number: it cannot connect to itself\n",
                           (unsigned long long)c->number);
            rc = 2;
            break;
        }
        p = npf_peers_find(c->peers, argv[start]);
        if (p) {
            /* connected already: the forwards given are added to it (what
             * npf forward PEER add does), the rest is as it was */
            npf_call *pc = npf_peer_call(p);
            char how[600] = "";
            size_t hl = 0;
            int nf = 0;
            npf_out_printf(o, "%s: already %s\n", npf_peer_shown(p),
                           pc && npf_call_state(pc) == NPF_CALL_ESTABLISHED ? "connected" : "a peer (connecting)");
            for (k = start + 1; k < i; k++) {                     /* names and nicks first */
                if (strcmp(argv[k], "--nick") == 0 && k + 1 < i) {     /* a new nick */
                    if (npf_nodes_set_nick(c, npf_peer_name(p), argv[k + 1], o) == 0)
                        npf_out_printf(o, "%s: nick \"%s\"\n", npf_peer_shown(p), argv[k + 1]);
                    else
                        rc = 1;
                    nf++;
                    k++;
                } else if (strcmp(argv[k], "-p") == 0 && k + 1 < i) {  /* its password: not paired yet */
                    if (pc && npf_call_state(pc) == NPF_CALL_ESTABLISHED)
                        ;                   /* connected: paired already */
                    else if (npf_peer_set_password(p, argv[k + 1]) == 0)
                        npf_out_printf(o, "%s: password given: connecting\n", npf_peer_shown(p));
                    else {
                        npf_out_printf(o, "%s: ended: delete it and add it again with its password\n", npf_peer_shown(p));
                        rc = 1;
                    }
                    nf++;
                    k++;
                } else if (strcmp(argv[k], "--name") == 0 && k + 1 < i) {     /* a new name */
                    if (npf_peers_name_set(c->peers, argv[k + 1], npf_peer_name(p), err, sizeof err) < 0) {
                        npf_out_printf(o, "%s\n", err);
                        rc = 1;
                    } else {
                        npf_out_printf(o, "%s: named %s\n", npf_peer_name(p), argv[k + 1]);
                    }
                    nf++;
                    k++;
                }
            }
            if (!rc && save && (npf_peer_tag(p) == PEER_TEMP || npf_peer_tag(p) == PEER_PLATFORM)) {
                /* temporary so far (or opened for platform mappings): saved
                 * from now on, with the forwards given here; the temporary
                 * ones stay temporary */
                npf_peer_set_tag(p, PEER_SAVED);
                npf_peer_set_persist(p, 1);
                if (save_peer(c, p, i - start, argv + start, 0) < 0) {
                    npf_out_printf(o, "%s: saved, but cannot write %s yet\n", npf_peer_shown(p), c->local_path);
                    unsaved = 1;
                } else
                    npf_out_printf(o, "%s: saved\n", npf_peer_shown(p));
                npf_log("peer %s saved", npf_peer_shown(p));
            }
            for (k = start + 1; k + 1 < i; k++) {
                if (npf_fwd_opt(argv[k])) {
                    int r = forward_one(c, p, 1, argv[k], argv[k + 1], save && npf_peer_tag(p) == PEER_SAVED, o);
                    if (r == NPF_CMD_UNSAVED)
                        unsaved = 1;
                    else if (r)
                        rc = 1;
                    if ((!r || r == NPF_CMD_UNSAVED) && hl < sizeof how)
                        hl += (size_t)snprintf(how + hl, sizeof how - hl, " %s %s", argv[k], argv[k + 1]);
                    nf++;
                    k++;
                } else if (strcmp(argv[k], "--nick") == 0 || strcmp(argv[k], "--name") == 0 || strcmp(argv[k], "-p") == 0) {
                    k++;
                }
            }
            if (hl)
                npf_out_printf(o, "(the same as: forward %s add%s)\n", npf_peer_shown(p), how);
            else if (!nf)
                npf_out_printf(o, "(add forwards to it with: forward %s add -L|-D|-R SPEC)\n", npf_peer_shown(p));
            start = i + 1;
            continue;
        }
        p = npf_peers_add(c->peers, i - start, argv + start, !(flags & NPF_PEER_ONCE), err, sizeof err);
        if (!p) {
            npf_out_printf(o, "%s\n", err);
            rc = 2;
            break;
        }
        for (k = start + 1; k + 1 < i; k++)
            if (strcmp(argv[k], "--nick") == 0 && npf_nodes_set_nick(c, npf_peer_name(p), argv[k + 1], o) != 0)
                rc = 1;
        npf_peer_set_tag(p, save ? PEER_SAVED : PEER_TEMP);
        npf_peer_set_persist(p, save);      /* saved: tried for ever, also when not paired yet */
        npf_peer_forward_mark(p, save);
        if (save && save_peer(c, p, i - start, argv + start, 1) < 0) {
            npf_out_printf(o, "%s: connecting, but cannot write %s yet\n", npf_peer_shown(p), c->local_path);
            unsaved = 1;
        } else {
            npf_out_printf(o, "%s: connecting%s\n", npf_peer_shown(p), save ? " (saved)" : "");
        }
        npf_log("peer %s added%s", npf_peer_shown(p), save ? " and saved" : "");
        added++;
        start = i + 1;
    }
    if (added)
        npf_start_peers(c);
    if (!rc && !seen) {
        npf_out_printf(o, "no peer given\n");
        rc = 2;
    }
    return rc ? rc : unsaved ? NPF_CMD_UNSAVED : 0;
}

/* not saved any more: not connected at the next start, no saved forwards
 * (the name, the nick and the pinned key stay) */
static void unsave_peer(npf_t *c, npf_peer *p)
{
    npf_ldev *d = npf_local_dev(&c->lc, npf_peer_name(p), 0);
    if (!d)
        return;
    d->save = 0;
    npf_local_fwd_clear(d);
    d->psk_file[0] = d->psk[0] = 0;
    npf_mods_fwds_saved(c, d);
    if (npf_local_save(&c->lc) < 0)
        npf_loge("cannot write %s", c->local_path);
}

int npf_cmd_peer_remove(npf_t *c, const char *name, int unsave, npf_out *o)
{
    npf_peer *p = npf_peers_find(c->peers, name);
    int saved, pm;
    if (!p) {
        npf_out_printf(o, "%s: not a node this one connects to\n", name);
        return 1;
    }
    if (npf_peer_tag(p) == PEER_PLATFORM) {
        npf_out_printf(o, "%s: opened for port mappings saved on the platform (removed there)\n", npf_peer_shown(p));
        return 1;
    }
    pm = npf_mods_peer_removing(c, p);      /* its platform mappings: back after (a module's) */
    saved = npf_peer_tag(p) == PEER_SAVED;
    if (saved && unsave)
        unsave_peer(c, p);
    if (npf_peer_tag(p) == PEER_FIXED)      /* npf.conf is not ours to change */
        npf_out_printf(o, "%s: disconnected; it is written in %s, so it connects again at the next start "
                          "(remove its line there)\n", npf_peer_shown(p), c->conf.path);
    else
        npf_out_printf(o, "%s: disconnected%s\n", npf_peer_shown(p),
                       saved ? (unsave ? ", removed from the configuration" : " (still in the configuration: back after a restart)")
                             : "");
    npf_log("peer %s removed%s", npf_peer_shown(p), saved && unsave ? " and unsaved" : "");
    npf_peers_remove(c->peers, p);
    if (pm) {
        npf_out_printf(o, "(its port mappings saved on the platform open a session to it again)\n");
        npf_mods_peer_removed(c);
    }
    return 0;
}

/* a saved peer's forward added (add) or taken out of local.json */
static int conf_peer_mapping(npf_t *c, const npf_peer *p, const char *opt, const char *spec, int add)
{
    npf_ldev *d = npf_local_dev(&c->lc, npf_peer_name(p), 0);
    if (!d || !d->save)
        return -1;
    if (add ? npf_local_fwd_add(d, opt, spec) < 0 : npf_local_fwd_del(d, opt, spec) < 0)
        return -1;
    npf_mods_fwds_saved(c, d);              /* my apps through it go with it (a module's) */
    return npf_local_save(&c->lc);
}

/* a peer opened for platform mappings whose last forward the user removed
 * (its mappings disabled meanwhile): closed, as the mappings would close it */
static void platform_peer_idle(npf_t *c, npf_peer *p)
{
    if (npf_peer_tag(p) != PEER_PLATFORM || npf_peer_forward_used(p) > 0)
        return;
    npf_mods_peer_removing(c, p);
    npf_log("%s: no mapping left, session closed", npf_peer_name(p));
    npf_peers_remove(c->peers, p);
}

/* forward [PEER]                                       list
 * forward PEER add -L|-D|-R SPEC... [--save]         add (several at once)
 * forward PEER del -L|-D|-R SPEC...                  remove */
#define FORWARD_USAGE "forward [NODE] | forward NODE add -L|-D|-R SPEC... [--save] | forward del NUMBER... | " \
                      "forward NODE del NUMBER|-L|-D|-R SPEC...\n"

/* a forward's option and spec by its number, on any peer (NULL: none) */
static npf_peer *forward_of(npf_t *c, int id, char opt[3], const char **spec)
{
    npf_peer *p;
    for (p = npf_peers_first(c->peers); p; p = npf_peer_next(p)) {
        int i = npf_peer_forward_by_id(p, id), perm;
        char o, st[8];
        if (i >= 0 && npf_peer_forward_info(p, i, &o, spec, &perm, st, sizeof st)) {
            opt[0] = '-', opt[1] = o, opt[2] = 0;
            return p;
        }
    }
    return NULL;
}

static int is_number(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return 0;
    return 1;
}

/* two exit codes as one: a failure over a change not saved over success */
static int merge_rc(int rc, int r)
{
    return !r || (rc && rc != NPF_CMD_UNSAVED) ? rc : r;
}

static int forward_one(npf_t *c, npf_peer *p, int add, const char *opt, const char *spec, int perm, npf_out *o)
{
    char err[300], nb[300];
    int i, saved = 0;
    spec = npf_peers_fwd_norm(c->peers, opt, spec, nb, sizeof nb);    /* as it is kept (a module's kind) */
    if (add) {
        if (perm && !npf_conf_value_ok(spec)) {
            npf_out_printf(o, "%s: the mapping must be one line without '#'\n", spec);
            return 2;
        }
        if (npf_peer_forward_add(p, opt, spec, perm, err, sizeof err) < 0) {
            npf_out_printf(o, "%s\n", err);
            return 2;
        }
        if (perm && conf_peer_mapping(c, p, opt, spec, 1) < 0) {
            npf_out_printf(o, "%s: %s %s added, but cannot write %s yet\n", npf_peer_shown(p), opt, spec,
                           c->local_path);
            npf_logw("%s: mapping %s %s added, %s not written", npf_peer_shown(p), opt, spec, c->local_path);
            return NPF_CMD_UNSAVED;
        }
        npf_out_printf(o, "%s: %s %s added%s\n", npf_peer_shown(p), opt, spec, perm ? " (saved)" : "");
        npf_log("%s: mapping %s %s added%s", npf_peer_shown(p), opt, spec, perm ? " and saved" : "");
        return 0;
    }
    if ((i = npf_peer_forward_del(p, opt, spec, &saved)) < 0) {
        if (i == -2)
            npf_out_printf(o, "%s: %s %s is saved on the platform (removed there)\n", npf_peer_shown(p), opt, spec);
        else
            npf_out_printf(o, "%s: no mapping %s %s\n", npf_peer_shown(p), opt, spec);
        return 1;
    }
    if (saved && conf_peer_mapping(c, p, opt, spec, 0) < 0) {
        npf_out_printf(o, "%s: %s %s removed, but cannot write %s yet\n",
                       npf_peer_shown(p), opt, spec, c->local_path);
        npf_logw("%s: mapping %s %s removed, %s not written", npf_peer_shown(p), opt, spec, c->local_path);
        return NPF_CMD_UNSAVED;
    }
    npf_out_printf(o, "%s: %s %s removed%s\n", npf_peer_shown(p), opt, spec, saved ? " (also from the configuration)" : "");
    npf_log("%s: mapping %s %s removed", npf_peer_shown(p), opt, spec);
    return 0;
}

int npf_cmd_forward(npf_t *c, int argc, char **argv, npf_out *o)
{
    const char *sub = argc > 1 ? argv[1] : "";
    npf_peer *p;
    int perm = 0, add, i, rc = 0, n = 0;
    if (argc > 1 && strcmp(argv[0], "del") == 0 && is_number(argv[1])) {
        /* del NUMBER...: the numbers are unique among the peers */
        for (i = 1; i < argc; i++) {
            char opt[3], spec[300];
            const char *sp;
            int r;
            if (!is_number(argv[i]) || !(p = forward_of(c, atoi(argv[i]), opt, &sp))) {
                npf_out_printf(o, "no forward number %s (forward lists them)\n", argv[i]);
                rc = merge_rc(rc, 1);
                continue;
            }
            snprintf(spec, sizeof spec, "%s", sp);
            r = forward_one(c, p, 0, opt, spec, 0, o);
            rc = merge_rc(rc, r);
            platform_peer_idle(c, p);
        }
        return rc;
    }
    if (argc > 0 && (strcmp(argv[0], "add") == 0 || strcmp(argv[0], "del") == 0)) {
        npf_out_printf(o, "the node comes first: forward NODE %s ...\n", argv[0]);
        return 2;
    }
    if (argc <= 1) {                        /* [PEER]: the forwards */
        if (argc > 0 && !npf_peers_find(c->peers, argv[0])) {
            npf_out_printf(o, "%s: not a node npf connects to\n", argv[0]);
            return 1;
        }
        for (p = npf_peers_first(c->peers); p; p = npf_peer_next(p))
            if (argc < 1 || npf_peers_find(c->peers, argv[0]) == p) {
                char a[400];
                npf_out_printf(o, "%s (%s)\n", peer_full(p, a, sizeof a), npf_cmd_tag_name(npf_peer_tag(p)));
                mappings_text(p, o);
            }
        return 0;
    }
    add = strcmp(sub, "add") == 0;
    if (!add && strcmp(sub, "del") != 0) {
        npf_out_printf(o, FORWARD_USAGE);
        return 2;
    }
    for (i = 2; i < argc; i++) {
        if (add && strcmp(argv[i], "--save") == 0)
            perm = 1;
        else if (!add && is_number(argv[i]))
            n++;
        else if (npf_fwd_opt(argv[i]) && i + 1 < argc)
            n++, i++;
        else
            n = -1000;
    }
    if (n <= 0) {
        npf_out_printf(o, FORWARD_USAGE);
        return 2;
    }
    if (!(p = npf_peers_find(c->peers, argv[0]))) {
        npf_out_printf(o, "%s: not a node npf connects to\n", argv[0]);
        return 1;
    }
    if (perm && npf_peer_tag(p) == PEER_FIXED) {
        npf_out_printf(o, "%s is defined in %s (read-only): save mappings with a node of node add\n",
                       npf_peer_shown(p), c->conf.path);
        return 2;
    }
    if (perm && npf_peer_tag(p) != PEER_SAVED) {
        npf_out_printf(o, "%s is a temporary peer: its mappings are temporary too "
                          "(node add keeps it)\n", npf_peer_shown(p));
        return 2;
    }
    for (i = 2; i < argc; i++) {
        int r;
        if (strcmp(argv[i], "--save") == 0)
            continue;
        if (!add && is_number(argv[i])) {   /* a number of this peer's forward */
            char opt[3], spec[300];
            const char *sp;
            if (forward_of(c, atoi(argv[i]), opt, &sp) != p) {
                npf_out_printf(o, "%s: no forward number %s (forward %s lists them)\n", npf_peer_shown(p), argv[i],
                               npf_peer_shown(p));
                rc = merge_rc(rc, 1);
                continue;
            }
            snprintf(spec, sizeof spec, "%s", sp);
            r = forward_one(c, p, 0, opt, spec, 0, o);
            rc = merge_rc(rc, r);
            continue;
        }
        r = forward_one(c, p, add, argv[i], argv[i + 1], perm, o);
        rc = merge_rc(rc, r);
        i++;
    }
    if (!add)
        platform_peer_idle(c, p);
    return rc;
}

/* node del NAME|NUMBER|HOST:PORT|all... [--forget]: disconnected and not
 * connected again; its name, nick and pinned key stay unless --forget */
static int node_del(npf_t *c, int argc, char **argv, npf_out *o)
{
    int i, forget = 0, rc = 0, n = 0;
    for (i = 0; i < argc; i++)
        if (strcmp(argv[i], "--forget") == 0)
            forget = 1;
    for (i = 0; i < argc; i++) {
        char tbuf[300];
        const char *target;
        npf_peer *p;
        if (strcmp(argv[i], "--forget") == 0)
            continue;
        n++;
        if (strcmp(argv[i], "all") == 0) {
            npf_peer *next;
            for (p = npf_peers_first(c->peers); p; p = next) {
                next = npf_peer_next(p);
                if (npf_peer_tag(p) != PEER_PLATFORM)
                    npf_cmd_peer_remove(c, npf_peer_name(p), 1, o);
            }
            if (forget) {
                c->lc.ndev = 0;
                npf_local_save(&c->lc);
                npf_out_printf(o, "every name, nick and key forgotten\n");
            }
            continue;
        }
        target = npf_peers_resolve(c->peers, argv[i], tbuf, sizeof tbuf);
        if ((p = npf_peers_find(c->peers, argv[i]))) {
            target = npf_peer_name(p);
            snprintf(tbuf, sizeof tbuf, "%s", target);
            target = tbuf;
            if (npf_cmd_peer_remove(c, argv[i], 1, o) != 0)
                rc = 1;
        } else if (!npf_local_dev(&c->lc, target, 0)) {
            npf_out_printf(o, "%s: not a node here (node lists them)\n", argv[i]);
            rc = 1;
            continue;
        } else if (!forget) {
            npf_out_printf(o, "%s: not connected; its name, nick and key are kept (--forget removes them)\n", argv[i]);
        }
        if (forget && npf_local_drop(&c->lc, target) == 0) {
            npf_local_save(&c->lc);
            npf_out_printf(o, "%s: name, nick and key forgotten\n", argv[i]);
        }
    }
    if (!n) {
        npf_out_printf(o, "node del NAME|NUMBER|HOST:PORT|all [--forget]\n");
        return 2;
    }
    return rc;
}

/* node                                    the nodes npf knows (async: the platform's list)
 * node add TARGET [options]... [--once]   saved (connected at every start) unless --once
 * node del TARGET... [--forget]
 * node set TARGET [--name NAME] [--nick TEXT]
 * node state TARGET                       the command line's wait after node add */
int npf_cmd_node(npf_t *c, int argc, char **argv, npf_text_cb cb, void *user, npf_out *o)
{
    const char *sub = argc > 1 ? argv[1] : "";
    if (argc == 1)
        return npf_cmd_nodes(c, 1, argv, cb, user, o);
    if (strcmp(sub, "add") == 0) {
        int i, k = 0, flags = NPF_PEER_SAVE;
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--once") == 0)    /* this time only: not saved, not reconnected */
                flags = NPF_PEER_ONCE;
            else if (strcmp(argv[i], "--temp") == 0)   /* npf run --node: not saved, reconnected */
                flags = 0;
            else
                argv[2 + k++] = argv[i];
        }
        return npf_cmd_peer_add(c, k, argv + 2, flags, o);
    }
    if (strcmp(sub, "del") == 0)
        return node_del(c, argc - 2, argv + 2, o);
    if (strcmp(sub, "set") == 0 && argc > 2)
        return npf_cmd_nodes(c, argc - 1, argv + 1, cb, user, o);
    if (strcmp(sub, "state") == 0 && argc > 2) {
        npf_peer *p = npf_peers_find(c->peers, argv[2]);
        char b[200];
        if (!p) {
            npf_out_printf(o, "%s: not a node here\n", argv[2]);
            return 3;
        }
        npf_peer_status(p, b, sizeof b);
        if (strcmp(b, "connected") == 0) {
            npf_out_printf(o, "%s: connected (%s)\n", npf_peer_shown(p), npf_call_path_label(npf_peer_call(p)));
            return 0;
        }
        npf_out_printf(o, "%s: %s\n", npf_peer_shown(p), b);
        return strncmp(b, "ended", 5) == 0 ? 3 : 1;
    }
    if (strcmp(sub, "wake") == 0 && argc > 2) {
        /* a page about to be used (the apps, the console): the session now,
         * not at its first connection */
        int i, rc = 0;
        for (i = 2; i < argc; i++) {
            npf_peer *p = npf_peers_find(c->peers, argv[i]);
            int r = p ? npf_peer_wake(p) : -2;
            if (r == -2)
                npf_out_printf(o, "%s: not a node here\n", argv[i]), rc = 3;
            else if (r < 0)
                npf_out_printf(o, "%s: ended\n", npf_peer_shown(p)), rc = 3;
            else
                npf_out_printf(o, "%s: %s\n", npf_peer_shown(p), r ? "has a session" : "connecting");
        }
        return rc;
    }
    npf_out_printf(o, "node | node add NUMBER|NAME|HOST:PORT [options] [--once] | node del NAME... [--forget] | "
                      "node set NAME [--name NAME] [--nick TEXT] | node wake NAME...\n");
    return 2;
}
