/* The node's messages: their tables (signaling.md, data-channel.md: the
 * types, lengths and ranges there are these) and where each one goes. */
#define _GNU_SOURCE
#include "npf/sys.h"
#include <stdio.h>
#include <string.h>

#include "../call/call_internal.h"
#include "home.h"
#include "msgs.h"
#include "node_internal.h"

/* the same lists as tables: each field an npf_field of the struct T */
#undef F_STR
#undef F_INT
#undef F_BOOL
#undef F_BOOLD
#undef F_B64
#undef F_B64X
#undef F_ADDR
#undef F_OBJ
#undef F_ARR
#undef F_TOK
#define F_STR(T, k, cap, fl)          {#k, NPF_F_STR, fl, offsetof(T, k), cap, 0, 0, 0, 0, NULL},
#define F_INT(T, k, fl, lo, hi, def)  {#k, NPF_F_INT, fl, offsetof(T, k), 0, 0, lo, hi, def, NULL},
#define F_BOOL(T, k)                  {#k, NPF_F_BOOL, 0, offsetof(T, k), 0, 0, 0, 0, 0, NULL},
#define F_BOOLD(T, k, fl, def)        {#k, NPF_F_BOOL, fl, offsetof(T, k), 0, 0, 0, 0, def, NULL},
#define F_B64(T, k, cap, fl, lo)      {#k, NPF_F_B64, fl, offsetof(T, k), cap, offsetof(T, k##_len), lo, 0, 0, NULL},
#define F_B64X(T, k, cap, fl)         {#k, NPF_F_B64, NPF_F_REQ | (fl), offsetof(T, k), cap, 0, cap, 0, 0, NULL},
#define F_ADDR(T, k, fl)              {#k, NPF_F_ADDR, fl, offsetof(T, k), 0, 0, 0, 0, 0, NULL},
#define F_OBJ(T, k, S, fl)            {#k, NPF_F_OBJ, fl, offsetof(T, k), 0, 0, 0, 0, 0, &S##_d},
#define F_ARR(T, k, S, cap, fl)       {#k, NPF_F_ARR, fl, offsetof(T, k), cap, offsetof(T, n##k), 0, 0, 0, &S##_d},
#define F_TOK(T, k, fl, jt)           {#k, NPF_F_TOK, fl, offsetof(T, k), 0, 0, jt, 0, 0, NULL},
#define TABLE(T, LIST) \
    static const npf_field T##_f[] = {LIST(T)}; \
    const npf_msgdesc T##_d = {#T, T##_f, sizeof T##_f / sizeof T##_f[0], sizeof(T)};

static const npf_field m_addr4_f[] = {{NULL, NPF_F_ADDR, NPF_F_V4, 0, 0, 0, 0, 0, 0, NULL}};
static const npf_field m_port_f[] = {{NULL, NPF_F_INT, 0, 0, 0, 0, 1, 65535, 0, NULL}};
static const npf_field m_s256_f[] = {{NULL, NPF_F_STR, NPF_F_REQ, 0, 256, 0, 0, 0, 0, NULL}};
const npf_msgdesc m_addr4_d = {"address", m_addr4_f, 1, sizeof(m_addr4)};
const npf_msgdesc m_port_d = {"port", m_port_f, 1, sizeof(m_port)};
const npf_msgdesc m_s256_d = {"string", m_s256_f, 1, sizeof(m_s256)};

TABLE(m_env, M_ENV)
TABLE(m_relay, M_RELAY)
TABLE(m_upgrade, M_UPGRADE)
TABLE(m_daykey, M_DAYKEY)
TABLE(m_welcome, M_WELCOME)
TABLE(m_enrolled, M_ENROLLED)
TABLE(m_server_list, M_SERVER_LIST)
TABLE(m_redirect, M_REDIRECT)
TABLE(m_relay_spare, M_RELAY_SPARE)
TABLE(m_home_open, M_HOME_OPEN)
TABLE(m_revoke, M_REVOKE)
TABLE(m_bind_committed, M_BIND_COMMITTED)
TABLE(m_app, M_APP)
TABLE(m_caller, M_CALLER)
TABLE(m_incoming, M_INCOMING)
TABLE(m_call_reply, M_CALL_REPLY)
TABLE(m_call_accepted, M_CALL_ACCEPTED)
TABLE(m_call_rejected, M_CALL_REJECTED)
TABLE(m_handshake, M_HANDSHAKE)
TABLE(m_cand, M_CAND)
TABLE(m_peer, M_PEER)
TABLE(m_punch_start, M_PUNCH_START)
TABLE(m_punch_info, M_PUNCH_INFO)
TABLE(m_relay_switch, M_RELAY_SWITCH)
TABLE(m_call_ended, M_CALL_ENDED)
TABLE(m_close, M_CLOSE)
TABLE(m_reverse_listen, M_REVERSE_LISTEN)
TABLE(m_listen_id, M_LISTEN_ID)
TABLE(m_listening, M_LISTENING)
TABLE(m_grant_update, M_GRANT_UPDATE)
TABLE(m_bind_approve, M_BIND_APPROVE)
TABLE(m_admin_get, M_ADMIN_GET)
TABLE(m_admin_key, M_ADMIN_KEY)
TABLE(m_admin_share_new, M_ADMIN_SHARE_NEW)
TABLE(m_admin_share_del, M_ADMIN_SHARE_DEL)
TABLE(m_admin_res_put, M_ADMIN_RES_PUT)
TABLE(m_admin_res_del, M_ADMIN_RES_DEL)
TABLE(m_server, M_SERVER)
TABLE(m_sources, M_SOURCES)
TABLE(m_list, M_LIST)
TABLE(m_paired, M_PAIRED)
TABLE(m_share, M_SHARE)
TABLE(m_revoked, M_REVOKED)
TABLE(m_state, M_STATE)
TABLE(m_forward, M_FORWARD)
TABLE(m_device, M_DEVICE)

/* a call's messages begin with its call_id: node_msg finds the call by it */
typedef char call_id_first[offsetof(m_call_accepted, call_id) + offsetof(m_call_rejected, call_id)
                           + offsetof(m_handshake, call_id) + offsetof(m_punch_start, call_id)
                           + offsetof(m_punch_info, call_id) + offsetof(m_relay_switch, call_id)
                           + offsetof(m_call_ended, call_id) == 0 ? 1 : -1];

const npf_msgdesc *const node_msgdescs[] = {
    &m_env_d, &m_relay_d, &m_upgrade_d, &m_welcome_d, &m_enrolled_d, &m_server_list_d, &m_redirect_d,
    &m_relay_spare_d, &m_home_open_d, &m_revoke_d, &m_bind_committed_d, &m_incoming_d, &m_call_reply_d,
    &m_call_accepted_d, &m_call_rejected_d, &m_handshake_d, &m_punch_start_d, &m_punch_info_d, &m_relay_switch_d,
    &m_call_ended_d, &m_close_d, &m_reverse_listen_d, &m_listen_id_d, &m_listening_d, &m_grant_update_d,
    &m_bind_approve_d, &m_admin_get_d, &m_admin_key_d, &m_admin_share_new_d, &m_admin_share_del_d, &m_admin_res_put_d,
    &m_admin_res_del_d, NULL,
};
const npf_msgdesc *const node_filedescs[] = {&m_list_d, &m_state_d, &m_device_d, NULL};

/* ---- dispatch ---- */

/* room for any of the messages below (NODE_MSG checks each struct's size, D each table) */
typedef union m_any {
    int64_t i;
    struct sockaddr_storage ss;
    uint8_t b[NODE_MSG_MAX];
} m_any;

/* a type, its table (NULL: nothing read), its handler: the node's, or a
 * call's (the call its call_id names; none, or ended: dropped); D: only a
 * message's table, whose struct fits m_any (NODE_MSG) */
#define D(T) (&T##_d + 0 * sizeof(T##_fits))
static const struct {
    const char *type;
    const npf_msgdesc *d;
    void (*node)(npf_node *n, const m_env *e, const void *m);
    void (*call)(npf_call *c, const void *m);
} handlers[] = {
    {"login", D(m_welcome), node_on_login, NULL},
    {"server_list", D(m_server_list), node_on_server_list, NULL},
    {"upgrade", D(m_upgrade), node_on_upgrade, NULL},
    {"probe", D(m_welcome), node_on_probe, NULL},
    {"keys", D(m_welcome), node_on_keys, NULL},
    {"account", D(m_welcome), node_on_account, NULL},
    {"replaced", NULL, node_on_replaced, NULL},
    {"redirect", D(m_redirect), node_on_redirect, NULL},
    {"relay_spare", D(m_relay_spare), node_on_relay_spare, NULL},
    {"incoming", D(m_incoming), node_on_incoming, NULL},
    {"punch_request", NULL, node_on_punch_request, NULL},
    {"revoke", D(m_revoke), node_on_revoke, NULL},
    {"bind_committed", D(m_bind_committed), node_on_bind_committed, NULL},
    {"call", D(m_call_reply), node_on_call, NULL},
    {"call_accepted", D(m_call_accepted), NULL, call_on_accepted},
    {"call_rejected", D(m_call_rejected), NULL, call_on_rejected},
    {"handshake", D(m_handshake), NULL, call_on_handshake},
    {"punch_start", D(m_punch_start), NULL, call_on_punch_start},
    {"punch_info", D(m_punch_info), NULL, call_on_punch_info},
    {"relay_switch", D(m_relay_switch), NULL, call_on_relay_switch},
    {"call_ended", D(m_call_ended), NULL, call_on_ended},
};

int node_env(const npf_json *j, m_env *e)
{
    char err[96];
    if (npf_msg_parse(&m_env_d, j, 0, e, err, sizeof err) < 0) {
        npf_logw("sig: a message refused (%s)", err);
        return -1;
    }
    e->j = j;
    return 0;
}

void node_msg(npf_node *n, const npf_json *j)
{
    m_env e;
    m_any u;
    char err[128];
    size_t i;
    if (node_env(j, &e) < 0)
        return;
    /* the envelope only (R10) */
    npf_logt("sig < %s%s%s%s%s%s%s%s%s, %zu bytes", e.type, e.id[0] ? " id=" : "", e.id, e.reply_to[0] ? " reply_to=" : "",
             e.reply_to, e.status[0] ? " " : "", e.status, e.error[0] ? " " : "", e.error, (size_t)j->len);
    if (e.reply_to[0] && node_sig_reply(n, &e))
        return;
    for (i = 0; i < sizeof handlers / sizeof handlers[0] && strcmp(handlers[i].type, e.type) != 0; i++)
        ;
    if (i == sizeof handlers / sizeof handlers[0]) {
        /* the platform's events for the program (mappings_changed, devices_changed ...) */
        if (!e.reply_to[0] && npf_json_get(j, e.data, "call_id") < 0 && n->hooks.on_event)
            n->hooks.on_event(n, e.type, j, e.data, n->hook_arg);
        return;
    }
    if (handlers[i].d && npf_msg_parse(handlers[i].d, j, e.data, &u, err, sizeof err) < 0) {
        npf_logw("sig: %s refused (%s)", e.type, err);
        if (e.id[0])
            npf_node_reply(n, e.type, e.id, "error", "bad_request", NULL);
    } else if (handlers[i].node) {
        handlers[i].node(n, &e, &u);
    } else {
        npf_call *c;
        for (c = n->calls; c && memcmp(c->call_id, &u, 16) != 0; c = c->next)
            ;
        if (c && !call_over(c))
            handlers[i].call(c, &u);
    }
    if (handlers[i].d)
        npf_msg_wipe(handlers[i].d, &u);
}
