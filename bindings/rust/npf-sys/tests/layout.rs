//! npf-sys structures against the C compiler: csrc/layout.c lists the same
//! sizes and offsets in the same order.
use core::mem::{offset_of, size_of};
use npf_sys::*;

extern "C" {
    static npf_sys_layout: [usize; N];
    static npf_sys_layout_count: usize;
}

const N: usize = 184;

#[test]
fn layout_matches_c() {
    let rust: [(usize, &str); N] = [
        (size_of::<npf_frame_info>(), "sizeof npf_frame_info"),
        (
            offset_of!(npf_frame_info, frame_no),
            "npf_frame_info.frame_no",
        ),
        (offset_of!(npf_frame_info, flags), "npf_frame_info.flags"),
        (
            offset_of!(npf_frame_info, lost_before),
            "npf_frame_info.lost_before",
        ),
        (size_of::<npf_callbacks>(), "sizeof npf_callbacks"),
        (offset_of!(npf_callbacks, size), "npf_callbacks.size"),
        (offset_of!(npf_callbacks, user), "npf_callbacks.user"),
        (offset_of!(npf_callbacks, log), "npf_callbacks.log"),
        (offset_of!(npf_callbacks, event), "npf_callbacks.event"),
        (offset_of!(npf_callbacks, session), "npf_callbacks.session"),
        (offset_of!(npf_callbacks, data), "npf_callbacks.data"),
        (
            offset_of!(npf_callbacks, media_open),
            "npf_callbacks.media_open",
        ),
        (
            offset_of!(npf_callbacks, media_frame),
            "npf_callbacks.media_frame",
        ),
        (
            offset_of!(npf_callbacks, media_closed),
            "npf_callbacks.media_closed",
        ),
        (size_of::<npf_setup>(), "sizeof npf_setup"),
        (offset_of!(npf_setup, size), "npf_setup.size"),
        (offset_of!(npf_setup, roots), "npf_setup.roots"),
        (offset_of!(npf_setup, nroots), "npf_setup.nroots"),
        (offset_of!(npf_setup, serverlist), "npf_setup.serverlist"),
        (
            offset_of!(npf_setup, serverlist_len),
            "npf_setup.serverlist_len",
        ),
        (
            offset_of!(npf_setup, serverlist_file),
            "npf_setup.serverlist_file",
        ),
        (
            offset_of!(npf_setup, serverlist_saved),
            "npf_setup.serverlist_saved",
        ),
        (offset_of!(npf_setup, server_url), "npf_setup.server_url"),
        (offset_of!(npf_setup, server_pub), "npf_setup.server_pub"),
        (offset_of!(npf_setup, doh_servers), "npf_setup.doh_servers"),
        (offset_of!(npf_setup, cred), "npf_setup.cred"),
        (offset_of!(npf_setup, password), "npf_setup.password"),
        (offset_of!(npf_setup, model_cred), "npf_setup.model_cred"),
        (offset_of!(npf_setup, serial), "npf_setup.serial"),
        (offset_of!(npf_setup, hw_info), "npf_setup.hw_info"),
        (offset_of!(npf_setup, model), "npf_setup.model"),
        (offset_of!(npf_setup, direct_host), "npf_setup.direct_host"),
        (offset_of!(npf_setup, direct_port), "npf_setup.direct_port"),
        (offset_of!(npf_setup, direct_psk), "npf_setup.direct_psk"),
        (offset_of!(npf_setup, udp_port), "npf_setup.udp_port"),
        (offset_of!(npf_setup, no_portmap), "npf_setup.no_portmap"),
        (offset_of!(npf_setup, relays_only), "npf_setup.relays_only"),
        (offset_of!(npf_setup, max_calls), "npf_setup.max_calls"),
        (
            offset_of!(npf_setup, punch_lead_ms),
            "npf_setup.punch_lead_ms",
        ),
        (
            offset_of!(npf_setup, punch_sockets),
            "npf_setup.punch_sockets",
        ),
        (
            offset_of!(npf_setup, no_host_report),
            "npf_setup.no_host_report",
        ),
        (
            offset_of!(npf_setup, no_hosted_trust),
            "npf_setup.no_hosted_trust",
        ),
        (offset_of!(npf_setup, peer_idle_s), "npf_setup.peer_idle_s"),
        (size_of::<npf_options>(), "sizeof npf_options"),
        (offset_of!(npf_options, size), "npf_options.size"),
        (offset_of!(npf_options, conf_dir), "npf_options.conf_dir"),
        (offset_of!(npf_options, data_dir), "npf_options.data_dir"),
        (offset_of!(npf_options, conf_file), "npf_options.conf_file"),
        (offset_of!(npf_options, overrides), "npf_options.overrides"),
        (offset_of!(npf_options, role), "npf_options.role"),
        (offset_of!(npf_options, log_level), "npf_options.log_level"),
        (offset_of!(npf_options, cb), "npf_options.cb"),
        (offset_of!(npf_options, app_name), "npf_options.app_name"),
        (offset_of!(npf_options, app_ver), "npf_options.app_ver"),
        (offset_of!(npf_options, runtime), "npf_options.runtime"),
        (offset_of!(npf_options, setup), "npf_options.setup"),
        (offset_of!(npf_options, flags), "npf_options.flags"),
        (size_of::<npf_peer_opt>(), "sizeof npf_peer_opt"),
        (offset_of!(npf_peer_opt, size), "npf_peer_opt.size"),
        (offset_of!(npf_peer_opt, target), "npf_peer_opt.target"),
        (offset_of!(npf_peer_opt, number), "npf_peer_opt.number"),
        (offset_of!(npf_peer_opt, host), "npf_peer_opt.host"),
        (offset_of!(npf_peer_opt, port), "npf_peer_opt.port"),
        (offset_of!(npf_peer_opt, psk), "npf_peer_opt.psk"),
        (offset_of!(npf_peer_opt, password), "npf_peer_opt.password"),
        (offset_of!(npf_peer_opt, connect), "npf_peer_opt.connect"),
        (offset_of!(npf_peer_opt, idle_ms), "npf_peer_opt.idle_ms"),
        (offset_of!(npf_peer_opt, flags), "npf_peer_opt.flags"),
        (offset_of!(npf_peer_opt, name), "npf_peer_opt.name"),
        (offset_of!(npf_peer_opt, nick), "npf_peer_opt.nick"),
        (offset_of!(npf_peer_opt, ctx), "npf_peer_opt.ctx"),
        (size_of::<npf_peer_info>(), "sizeof npf_peer_info"),
        (offset_of!(npf_peer_info, target), "npf_peer_info.target"),
        (offset_of!(npf_peer_info, number), "npf_peer_info.number"),
        (offset_of!(npf_peer_info, host), "npf_peer_info.host"),
        (offset_of!(npf_peer_info, port), "npf_peer_info.port"),
        (offset_of!(npf_peer_info, name), "npf_peer_info.name"),
        (offset_of!(npf_peer_info, nick), "npf_peer_info.nick"),
        (offset_of!(npf_peer_info, connect), "npf_peer_info.connect"),
        (offset_of!(npf_peer_info, flags), "npf_peer_info.flags"),
        (offset_of!(npf_peer_info, saved), "npf_peer_info.saved"),
        (offset_of!(npf_peer_info, state), "npf_peer_info.state"),
        (offset_of!(npf_peer_info, needs), "npf_peer_info.needs"),
        (
            offset_of!(npf_peer_info, retry_in_ms),
            "npf_peer_info.retry_in_ms",
        ),
        (
            offset_of!(npf_peer_info, end_reason),
            "npf_peer_info.end_reason",
        ),
        (offset_of!(npf_peer_info, why), "npf_peer_info.why"),
        (offset_of!(npf_peer_info, session), "npf_peer_info.session"),
        (
            offset_of!(npf_peer_info, nforwards),
            "npf_peer_info.nforwards",
        ),
        (offset_of!(npf_peer_info, ctx), "npf_peer_info.ctx"),
        (size_of::<npf_endpoint>(), "sizeof npf_endpoint"),
        (offset_of!(npf_endpoint, host), "npf_endpoint.host"),
        (offset_of!(npf_endpoint, port), "npf_endpoint.port"),
        (size_of::<npf_forward_opt>(), "sizeof npf_forward_opt"),
        (offset_of!(npf_forward_opt, size), "npf_forward_opt.size"),
        (offset_of!(npf_forward_opt, kind), "npf_forward_opt.kind"),
        (offset_of!(npf_forward_opt, proto), "npf_forward_opt.proto"),
        (
            offset_of!(npf_forward_opt, listen),
            "npf_forward_opt.listen",
        ),
        (
            offset_of!(npf_forward_opt, target),
            "npf_forward_opt.target",
        ),
        (offset_of!(npf_forward_opt, flags), "npf_forward_opt.flags"),
        (offset_of!(npf_forward_opt, ctx), "npf_forward_opt.ctx"),
        (size_of::<npf_forward_info>(), "sizeof npf_forward_info"),
        (offset_of!(npf_forward_info, peer), "npf_forward_info.peer"),
        (offset_of!(npf_forward_info, kind), "npf_forward_info.kind"),
        (
            offset_of!(npf_forward_info, proto),
            "npf_forward_info.proto",
        ),
        (
            offset_of!(npf_forward_info, flags),
            "npf_forward_info.flags",
        ),
        (
            offset_of!(npf_forward_info, saved),
            "npf_forward_info.saved",
        ),
        (
            offset_of!(npf_forward_info, listen_host),
            "npf_forward_info.listen_host",
        ),
        (
            offset_of!(npf_forward_info, listen_port),
            "npf_forward_info.listen_port",
        ),
        (
            offset_of!(npf_forward_info, target_host),
            "npf_forward_info.target_host",
        ),
        (
            offset_of!(npf_forward_info, target_port),
            "npf_forward_info.target_port",
        ),
        (
            offset_of!(npf_forward_info, state),
            "npf_forward_info.state",
        ),
        (
            offset_of!(npf_forward_info, why_code),
            "npf_forward_info.why_code",
        ),
        (offset_of!(npf_forward_info, why), "npf_forward_info.why"),
        (
            offset_of!(npf_forward_info, conns),
            "npf_forward_info.conns",
        ),
        (
            offset_of!(npf_forward_info, refused),
            "npf_forward_info.refused",
        ),
        (
            offset_of!(npf_forward_info, refused_why),
            "npf_forward_info.refused_why",
        ),
        (offset_of!(npf_forward_info, ctx), "npf_forward_info.ctx"),
        (size_of::<npf_resource>(), "sizeof npf_resource"),
        (offset_of!(npf_resource, size), "npf_resource.size"),
        (offset_of!(npf_resource, type_), "npf_resource.type"),
        (offset_of!(npf_resource, name), "npf_resource.name"),
        (offset_of!(npf_resource, svc), "npf_resource.svc"),
        (offset_of!(npf_resource, service), "npf_resource.service"),
        (offset_of!(npf_resource, rule), "npf_resource.rule"),
        (offset_of!(npf_resource, path), "npf_resource.path"),
        (offset_of!(npf_resource, desc), "npf_resource.desc"),
        (offset_of!(npf_resource, flags), "npf_resource.flags"),
        (size_of::<npf_resource_info>(), "sizeof npf_resource_info"),
        (
            offset_of!(npf_resource_info, type_),
            "npf_resource_info.type",
        ),
        (
            offset_of!(npf_resource_info, flags),
            "npf_resource_info.flags",
        ),
        (
            offset_of!(npf_resource_info, saved),
            "npf_resource_info.saved",
        ),
        (
            offset_of!(npf_resource_info, name),
            "npf_resource_info.name",
        ),
        (offset_of!(npf_resource_info, svc), "npf_resource_info.svc"),
        (
            offset_of!(npf_resource_info, host),
            "npf_resource_info.host",
        ),
        (
            offset_of!(npf_resource_info, port),
            "npf_resource_info.port",
        ),
        (
            offset_of!(npf_resource_info, rule),
            "npf_resource_info.rule",
        ),
        (
            offset_of!(npf_resource_info, path),
            "npf_resource_info.path",
        ),
        (
            offset_of!(npf_resource_info, desc),
            "npf_resource_info.desc",
        ),
        (size_of::<npf_pairing>(), "sizeof npf_pairing"),
        (offset_of!(npf_pairing, key), "npf_pairing.key"),
        (offset_of!(npf_pairing, since), "npf_pairing.since"),
        (offset_of!(npf_pairing, admin), "npf_pairing.admin"),
        (size_of::<npf_node_info>(), "sizeof npf_node_info"),
        (offset_of!(npf_node_info, number), "npf_node_info.number"),
        (offset_of!(npf_node_info, role), "npf_node_info.role"),
        (offset_of!(npf_node_info, online), "npf_node_info.online"),
        (offset_of!(npf_node_info, server), "npf_node_info.server"),
        (
            offset_of!(npf_node_info, account_id),
            "npf_node_info.account_id",
        ),
        (
            offset_of!(npf_node_info, enrolling),
            "npf_node_info.enrolling",
        ),
        (offset_of!(npf_node_info, nat), "npf_node_info.nat"),
        (
            offset_of!(npf_node_info, nat_filtering),
            "npf_node_info.nat_filtering",
        ),
        (
            offset_of!(npf_node_info, public_addr),
            "npf_node_info.public_addr",
        ),
        (
            offset_of!(npf_node_info, udp_port),
            "npf_node_info.udp_port",
        ),
        (offset_of!(npf_node_info, started), "npf_node_info.started"),
        (offset_of!(npf_node_info, peers), "npf_node_info.peers"),
        (
            offset_of!(npf_node_info, sessions),
            "npf_node_info.sessions",
        ),
        (offset_of!(npf_node_info, unsaved), "npf_node_info.unsaved"),
        (size_of::<npf_session_info>(), "sizeof npf_session_info"),
        (offset_of!(npf_session_info, peer), "npf_session_info.peer"),
        (
            offset_of!(npf_session_info, number),
            "npf_session_info.number",
        ),
        (
            offset_of!(npf_session_info, outgoing),
            "npf_session_info.outgoing",
        ),
        (offset_of!(npf_session_info, path), "npf_session_info.path"),
        (
            offset_of!(npf_session_info, call_id),
            "npf_session_info.call_id",
        ),
        (size_of::<npf_media_opt>(), "sizeof npf_media_opt"),
        (offset_of!(npf_media_opt, size), "npf_media_opt.size"),
        (offset_of!(npf_media_opt, tag), "npf_media_opt.tag"),
        (offset_of!(npf_media_opt, prio), "npf_media_opt.prio"),
        (
            offset_of!(npf_media_opt, max_age_ms),
            "npf_media_opt.max_age_ms",
        ),
        (
            offset_of!(npf_media_opt, drop_until_key),
            "npf_media_opt.drop_until_key",
        ),
        (offset_of!(npf_media_opt, fec), "npf_media_opt.fec"),
        (
            offset_of!(npf_media_opt, fec_ratio),
            "npf_media_opt.fec_ratio",
        ),
        (
            offset_of!(npf_media_opt, latency_rtt),
            "npf_media_opt.latency_rtt",
        ),
        (
            offset_of!(npf_media_opt, rcv_drop_until_key),
            "npf_media_opt.rcv_drop_until_key",
        ),
        (size_of::<npf_media_stats>(), "sizeof npf_media_stats"),
        (
            offset_of!(npf_media_stats, target_rate),
            "npf_media_stats.target_rate",
        ),
        (
            offset_of!(npf_media_stats, srtt_ms),
            "npf_media_stats.srtt_ms",
        ),
        (
            offset_of!(npf_media_stats, min_rtt_ms),
            "npf_media_stats.min_rtt_ms",
        ),
        (
            offset_of!(npf_media_stats, frames_dropped),
            "npf_media_stats.frames_dropped",
        ),
        (
            offset_of!(npf_media_stats, frames_skipped),
            "npf_media_stats.frames_skipped",
        ),
        (
            offset_of!(npf_media_stats, fec_recovered),
            "npf_media_stats.fec_recovered",
        ),
        (
            offset_of!(npf_media_stats, peer_frame_delay_avg_ms),
            "npf_media_stats.peer_frame_delay_avg_ms",
        ),
        (
            offset_of!(npf_media_stats, peer_frame_delay_max_ms),
            "npf_media_stats.peer_frame_delay_max_ms",
        ),
        (
            offset_of!(npf_media_stats, peer_jitter_ms),
            "npf_media_stats.peer_jitter_ms",
        ),
        (
            offset_of!(npf_media_stats, capacity_short),
            "npf_media_stats.capacity_short",
        ),
    ];
    let (c, count) = unsafe { (&npf_sys_layout, npf_sys_layout_count) };
    assert_eq!(count, N, "csrc/layout.c and this list differ in length");
    let bad: Vec<String> = rust
        .iter()
        .zip(c.iter())
        .filter(|((r, _), c)| r != *c)
        .map(|((r, n), c)| format!("{n}: rust {r}, C {c}"))
        .collect();
    assert!(bad.is_empty(), "layout differs:\n{}", bad.join("\n"));
}
