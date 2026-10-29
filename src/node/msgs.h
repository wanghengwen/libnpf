/* The node's signaling messages and the tunnel's control messages, each the
 * list of its fields as signaling.md and data-channel.md give them, and the
 * server list and the node's files (state.json, local.json): the list
 * makes the message's struct here and its table in msgs.c (npf/msg.h), so
 * that what a handler reads is what the parser checked. A field is
 * F_<type>(T, key, ...), fl its NPF_F_* flags; messages to a call begin
 * with its call_id. */
#ifndef NPF_NODE_MSGS_H
#define NPF_NODE_MSGS_H

#include "npf/callee.h"
#include "npf/local.h"
#include "npf/msg.h"
#include "npf/node.h"

#define F_REQ    NPF_F_REQ
#define F_SECRET NPF_F_SECRET
#define F_SKIP   NPF_F_SKIP
#define F_V4     NPF_F_V4
#define F_STRICT NPF_F_STRICT

#define F_STR(T, k, cap, fl)            char k[cap];
#define F_INT(T, k, fl, lo, hi, def)    int64_t k;          /* absent: def */
#define F_BOOL(T, k)                    int k;
#define F_BOOLD(T, k, fl, def)          int k;              /* absent: def */
#define F_B64(T, k, cap, fl, lo)        uint8_t k[cap]; int k##_len;    /* lo..cap bytes, k_len 0 absent */
#define F_B64X(T, k, cap, fl)           uint8_t k[cap];     /* required, of cap bytes */
#define F_ADDR(T, k, fl)                struct sockaddr_storage k;
#define F_OBJ(T, k, S, fl)              S k;
#define F_ARR(T, k, S, cap, fl)         S k[cap]; int n##k;
#define F_TOK(T, k, fl, jt)             int k;              /* its token, -1 absent */
#define F_TIME_MAX                      (1LL << 50)         /* Unix ms: 35 000 years; sums of two never overflow */
#define NODE_MSG_MAX                    4096                /* a message's struct (node_msg's room) */
#define NODE_FILE(T, LIST)              typedef struct T { LIST(T) } T; extern const npf_msgdesc T##_d;
#define NODE_MSG(T, LIST)               NODE_FILE(T, LIST) typedef char T##_fits[sizeof(T) <= NODE_MSG_MAX ? 1 : -1];

/* the envelope (signaling.md "公共消息格式"); j: the message */
#define M_ENV(T) F_INT(T, v, F_REQ, 1, 1, 0) F_STR(T, type, 32, F_REQ) F_STR(T, id, 24, 0) F_STR(T, reply_to, 24, 0) \
    F_STR(T, status, 16, 0) F_STR(T, error, 32, 0) F_STR(T, message, 64, 0) F_TOK(T, data, F_REQ, NPF_JT_OBJECT)
typedef struct m_env { M_ENV(m_env) const npf_json *j; } m_env;
extern const npf_msgdesc m_env_d;

/* the elements of arrays of single values: an IPv4 address, a port, a string not empty */
typedef struct sockaddr_storage m_addr4;
typedef int64_t m_port;
typedef char m_s256[256];
extern const npf_msgdesc m_addr4_d, m_port_d, m_s256_d;

/* a relay allocation (signaling.md "公共字段"): mode "" none; IPv4 addresses only */
#define M_WS(T) F_STR(T, url, 256, F_REQ) F_INT(T, server_id, 0, 0, 1 << 30, 0)
NODE_MSG(m_ws, M_WS)
#define M_RELAY(T) F_STR(T, mode, 8, F_REQ) F_B64X(T, relay_id, 8, 0) F_B64X(T, alloc_key, 32, F_SECRET) \
    F_ARR(T, udp, m_addr4, 4, F_SKIP) F_OBJ(T, ws, m_ws, 0) F_BOOL(T, spare)
NODE_MSG(m_relay, M_RELAY)

/* ---- access (signaling.md "接入与服务器列表") ---- */

/* upgrade, welcome's upgrade, upgrade_required's data (packages: the array's token) */
#define M_UPGRADE(T) F_BOOL(T, required) F_STR(T, min, 40, 0) F_STR(T, latest, 40, 0) F_STR(T, url, 320, 0) \
    F_STR(T, notes, 320, 0) F_TOK(T, packages, 0, NPF_JT_ARRAY)
NODE_MSG(m_upgrade, M_UPGRADE)
#define M_DAYKEY(T) F_INT(T, day, F_REQ, 0, INT32_MAX, 0) F_B64X(T, key, 32, F_SECRET)
NODE_MSG(m_daykey, M_DAYKEY)
/* login's reply; "keys" and "probe" carry some of its fields (server_list:
 * the token of 64 KB at most, decoded by its handler) */
#define M_WELCOME(T) F_INT(T, time, 0, 0, F_TIME_MAX, -1) F_INT(T, server_id, 0, 0, 1 << 30, -1) \
    F_INT(T, ping_s, 0, 5, 3600, 0) F_STR(T, client_id, 24, 0) F_STR(T, account_id, 24, 0) \
    F_TOK(T, upgrade, 0, NPF_JT_OBJECT) F_B64(T, ticket, 28, F_SECRET, 28) F_ARR(T, probe_keys, m_daykey, 2, F_SKIP) \
    F_ARR(T, probe, m_addr4, 3, F_SKIP) F_B64(T, cert, 1024, 0, 1) F_B64(T, account_cert, 1024, 0, 1) \
    F_TOK(T, server_list, 0, NPF_JT_STRING)
NODE_MSG(m_welcome, M_WELCOME)
#define M_ENROLLED(T) F_STR(T, number, 24, F_REQ) F_B64(T, cert, 1024, F_REQ, 1)
NODE_MSG(m_enrolled, M_ENROLLED)
#define M_SERVER_LIST(T) F_TOK(T, blob, F_REQ, NPF_JT_STRING)
NODE_MSG(m_server_list, M_SERVER_LIST)
#define M_REDIRECT(T) F_INT(T, server_id, F_REQ, 0, 1 << 30, 0)
NODE_MSG(m_redirect, M_REDIRECT)

/* ---- the spare, revocations, bindings ---- */

#define M_RELAY_SPARE(T) F_OBJ(T, relay, m_relay, F_REQ) F_STR(T, why, 16, 0)
NODE_MSG(m_relay_spare, M_RELAY_SPARE)
#define M_HOME_OPEN(T) F_OBJ(T, relay, m_relay, 0) F_B64(T, relay_id, 8, 0, 8) F_BOOL(T, resumed)   /* the reply */
NODE_MSG(m_home_open, M_HOME_OPEN)
#define M_REVOKE(T) F_STR(T, account_id, 24, F_REQ) F_INT(T, before, F_REQ, 0, INT64_MAX, 0) F_BOOL(T, owner)
NODE_MSG(m_revoke, M_REVOKE)
#define M_BIND_COMMITTED(T) F_STR(T, account_id, 24, F_REQ) F_B64X(T, operation_id, 16, 0)
NODE_MSG(m_bind_committed, M_BIND_COMMITTED)

/* ---- calls (signaling.md "呼叫与端到端连接") ---- */

#define M_APP(T) F_STR(T, name, 33, F_REQ) F_STR(T, ver, 33, F_REQ)
NODE_MSG(m_app, M_APP)
#define M_CALLER(T) F_STR(T, kind, 8, 0) F_STR(T, id, 24, 0) F_OBJ(T, app, m_app, 0) F_BOOL(T, hosted)
NODE_MSG(m_caller, M_CALLER)
#define M_INCOMING(T) F_B64X(T, call_id, 16, 0) F_OBJ(T, caller, m_caller, 0) F_STR(T, auth, 8, F_REQ) \
    F_B64(T, hs, 512, F_REQ, 1) F_B64(T, grant, 512, F_SECRET, 1) F_B64(T, cpace, 32, 0, 32) F_BOOL(T, secure) \
    F_OBJ(T, relay, m_relay, 0)
NODE_MSG(m_incoming, M_INCOMING)
#define M_CALL_REPLY(T) F_OBJ(T, relay, m_relay, 0)
NODE_MSG(m_call_reply, M_CALL_REPLY)
#define M_CALL_ACCEPTED(T) F_B64X(T, call_id, 16, 0) F_B64(T, hs, 512, F_REQ, 1) F_B64(T, cpace, 32, 0, 32) \
    F_BOOL(T, secure) F_OBJ(T, relay, m_relay, 0)
NODE_MSG(m_call_accepted, M_CALL_ACCEPTED)
#define M_CALL_REJECTED(T) F_B64X(T, call_id, 16, 0) F_STR(T, error, 32, 0)
NODE_MSG(m_call_rejected, M_CALL_REJECTED)
#define M_HANDSHAKE(T) F_B64X(T, call_id, 16, 0) F_INT(T, step, F_REQ, 3, 3, 0) F_B64(T, msg, 512, F_REQ, 1)
NODE_MSG(m_handshake, M_HANDSHAKE)
#define M_CAND(T) F_STR(T, t, 8, 0) F_ADDR(T, a, F_REQ)
NODE_MSG(m_cand, M_CAND)
#define M_PEER(T) F_ARR(T, cand, m_cand, 16, F_SKIP) F_STR(T, pub_ip, 64, 0)
NODE_MSG(m_peer, M_PEER)
/* the ranges and defaults of signaling.md "punch_start" (start_at -1: none) */
#define M_PUNCH_START(T) F_B64X(T, call_id, 16, 0) F_INT(T, round, F_REQ, 1, 1000, 0) F_STR(T, skip, 16, 0) \
    F_STR(T, strategy, 8, 0) F_STR(T, side, 8, 0) F_B64(T, punch_id, 8, 0, 8) F_B64(T, punch_key, 32, F_SECRET, 32) \
    F_OBJ(T, peer, m_peer, 0) F_ARR(T, range, m_port, 2, 0) F_INT(T, m_total, 0, 0, 4000, 1024) \
    F_INT(T, pps, 0, 1, 1000, 200) F_INT(T, n_sockets, 0, 0, 256, 0) F_INT(T, timeout_ms, 0, 1000, 600000, 8000) \
    F_INT(T, delta, 0, -64, 64, 0) F_INT(T, peer_delta, 0, -64, 64, 0) F_INT(T, window, 0, 1, 128, 32) \
    F_INT(T, passes, 0, 1, 8, 4) F_INT(T, peer_n, 0, 1, 256, 0) F_INT(T, start_at, 0, 0, F_TIME_MAX, -1)
NODE_MSG(m_punch_start, M_PUNCH_START)
#define M_PUNCH_INFO(T) F_B64X(T, call_id, 16, 0) F_INT(T, round, F_REQ, 0, 1000, 0) F_INT(T, port, 0, 1024, 65535, 0) \
    F_BOOL(T, stop) F_OBJ(T, cand, m_cand, 0)
NODE_MSG(m_punch_info, M_PUNCH_INFO)
#define M_RELAY_SWITCH(T) F_B64X(T, call_id, 16, 0) F_OBJ(T, relay, m_relay, 0)
NODE_MSG(m_relay_switch, M_RELAY_SWITCH)
#define M_CALL_ENDED(T) F_B64X(T, call_id, 16, 0) F_STR(T, reason, 32, 0)
NODE_MSG(m_call_ended, M_CALL_ENDED)

/* ---- the tunnel's control messages (data-channel.md 7, signaling.md "隧道内控制消息") ---- */

#define M_CLOSE(T) F_STR(T, reason, 32, 0)
NODE_MSG(m_close, M_CLOSE)
#define M_REVERSE_LISTEN(T) F_STR(T, bind, 64, F_STRICT) F_INT(T, port, F_STRICT, 0, 65535, 0) \
    F_STR(T, target_host, 256, F_REQ) F_INT(T, target_port, F_REQ, 1, 65535, 0) F_BOOLD(T, udp, F_STRICT, 0)
NODE_MSG(m_reverse_listen, M_REVERSE_LISTEN)
#define M_LISTEN_ID(T) F_INT(T, listen_id, F_REQ, 1, UINT32_MAX, 0)
NODE_MSG(m_listen_id, M_LISTEN_ID)
#define M_LISTENING(T) F_INT(T, listen_id, F_REQ, 1, UINT32_MAX, 0) F_INT(T, port, F_REQ, 1, 65535, 0)   /* the reply */
NODE_MSG(m_listening, M_LISTENING)
#define M_GRANT_UPDATE(T) F_B64(T, grant, 512, F_REQ | F_SECRET, 1)
NODE_MSG(m_grant_update, M_GRANT_UPDATE)
#define M_BIND_APPROVE(T) F_STR(T, account_id, 24, F_REQ) F_B64X(T, operation_id, 16, 0) F_B64X(T, challenge, 16, 0) \
    F_INT(T, expires, F_REQ, 0, INT64_MAX, 0)
NODE_MSG(m_bind_approve, M_BIND_APPROVE)

/* ---- the server list (signaling.md "服务器列表") and the node's files ---- */

#define M_SERVER(T) F_INT(T, id, F_REQ, 0, 1 << 30, 0) F_INT(T, prio, 0, 0, 1000, 1) F_INT(T, weight, 0, 0, 1000, 1) \
    F_B64X(T, dh_pub, 32, 0) F_ARR(T, ws, m_s256, 2, F_REQ | F_SKIP)
NODE_MSG(m_server, M_SERVER)
#define M_SOURCES(T) F_ARR(T, doh, m_s256, NPF_SOURCES_MAX, F_SKIP) F_ARR(T, https, m_s256, NPF_SOURCES_MAX, F_SKIP)
NODE_MSG(m_sources, M_SOURCES)
#define M_LIST(T) F_INT(T, serial, F_REQ, 0, INT64_MAX, 0) F_ARR(T, servers, m_server, NPF_MAX_SERVERS, F_REQ | F_SKIP) \
    F_INT(T, expires, 0, 0, INT64_MAX, 0) F_BOOLD(T, full, 0, 1) F_OBJ(T, sources, m_sources, 0)
NODE_FILE(m_list, M_LIST)

/* state.json (callee.c; password: its token, any string) */
#define M_PAIRED(T) F_B64X(T, pub, 32, 0) F_INT(T, added, 0, 0, INT64_MAX, 0)
NODE_MSG(m_paired, M_PAIRED)
#define M_REVOKED(T) F_STR(T, account, 32, F_REQ) F_INT(T, before, F_REQ, 0, INT64_MAX, 0)
NODE_MSG(m_revoked, M_REVOKED)
#define M_STATE(T) F_TOK(T, password, 0, NPF_JT_STRING) F_ARR(T, paired, m_paired, NPF_MAX_PAIRED, F_SKIP) \
    F_INT(T, fails, 0, 0, 1000000, 0) F_INT(T, locked_until, 0, 0, INT64_MAX, 0) F_INT(T, lock_secs, 0, 0, INT64_MAX, 0) \
    F_B64(T, cert, 1024, 0, 1) F_STR(T, owner, 32, 0) F_INT(T, owner_reset_pending, 0, 0, 1, 0) \
    F_ARR(T, revokes, m_revoked, NPF_MAX_REVOKES, F_SKIP)
NODE_FILE(m_state, M_STATE)

/* a device's record in local.json (local.c, local.h); the other keys are the modules' */
#define M_FORWARD(T) F_STR(T, kind, 16, 0) F_STR(T, proto, 8, 0) F_STR(T, listen, 64, 0) F_INT(T, port, 0, 0, 65535, 0) \
    F_STR(T, host, 256, 0) F_INT(T, hostport, 0, 0, 65535, 0) F_STR(T, spec, 300, 0)
NODE_MSG(m_forward, M_FORWARD)
#define M_DEVICE(T) F_STR(T, name, 33, 0) F_STR(T, nick, NPF_NICK_MAX + 1, 0) F_BOOL(T, save) F_STR(T, connect, 16, 0) \
    F_INT(T, idle_ms, 0, 0, 86400000, 0) F_STR(T, psk_file, 512, 0) F_STR(T, psk, 64, F_SECRET) \
    F_ARR(T, forwards, m_forward, NPF_LOCAL_MAX_FWD, F_SKIP) F_B64(T, key, 32, 0, 32) F_TOK(T, resources, 0, NPF_JT_ARRAY)
NODE_FILE(m_device, M_DEVICE)

/* every table, NULL at the end (the tests, the fuzzer): the messages', the
 * server list's and the files' */
extern const npf_msgdesc *const node_msgdescs[], *const node_filedescs[];

/* the message at the root of j into e (its envelope): 0, or -1 (logged) */
int  node_env(const npf_json *j, m_env *e);
/* a signaling message: a request's reply to its callback, the rest to its
 * handler (a message to a call: to that call), a platform event to the hooks */
void node_msg(npf_node *n, const npf_json *j);

#endif
