// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bpf_compat.h"
#include "shared_network.h"
#include "force_intercept_policy.h"
#include "shared_network_packet.h"
#include "private_address.h"

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#define SB_SHARED_POLICY_BYPASS 0U
#define SB_SHARED_POLICY_PROXY 1U
#define SB_SHARED_POLICY_CACHE_BYPASS 2U
#define SB_SHARED_POLICY_CONTINUE 3U
#define SB_SHARED_POLICY_RESPECT_SOURCE 4U

// TCX only continues with later TCX programs and the legacy clsact chain for
// TC_ACT_UNSPEC. TC_ACT_PIPE stops the TCX program array before being mapped
// to "next", which can skip tethering programs attached after sing-ebpf.
#define SB_SHARED_ACT_CONTINUE TC_ACT_UNSPEC

#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)
#endif

#define EXTERNAL_MAP(name, key_type, value_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = BPF_MAP_TYPE_HASH, \
        .key_size = sizeof(key_type), \
        .value_size = sizeof(value_type), \
        .max_entries = entries, \
    }

SB_FORCE_MAPS(shared);

EXTERNAL_MAP(shared_control, __u32, struct sb_shared_control, 1U);
struct bpf_map_def SEC("maps") shared_stats = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = SB_SHARED_STAT_COUNT,
};
EXTERNAL_MAP(shared_flow_by_original, struct sb_shared_original_key, struct sb_shared_token_value, SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES);
struct bpf_map_def SEC("maps") shared_bypass_flow = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct sb_shared_original_key),
    .value_size = sizeof(struct sb_shared_bypass_flow_value),
    .max_entries = SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES,
};
EXTERNAL_MAP(shared_flow_by_token, struct sb_shared_listener_key, struct sb_shared_original_value, SB_SHARED_NETWORK_OBJECT_MAP_ENTRIES);
EXTERNAL_MAP(shared_host_ipv4, struct sb_lpm4_key, __u8, 256U);
EXTERNAL_MAP(shared_host_ipv6, struct sb_lpm6_key, __u8, 256U);
EXTERNAL_MAP(shared_include_source_ipv4, struct sb_lpm4_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_include_source_ipv6, struct sb_lpm6_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_exclude_source_ipv4, struct sb_lpm4_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_exclude_source_ipv6, struct sb_lpm6_key, __u8, SB_SHARED_SOURCE_CIDR_MAP_ENTRIES);
EXTERNAL_MAP(shared_include_source_mac, struct sb_shared_mac_key, __u8, SB_SHARED_SOURCE_MAC_MAP_ENTRIES);
EXTERNAL_MAP(shared_exclude_source_mac, struct sb_shared_mac_key, __u8, SB_SHARED_SOURCE_MAC_MAP_ENTRIES);
EXTERNAL_MAP(shared_bypass_port, struct sb_shared_port_key, __u8, 4096U);
EXTERNAL_MAP(shared_bypass_ipv4, struct sb_lpm4_key, __u8, 65536U);
EXTERNAL_MAP(shared_bypass_ipv6, struct sb_lpm6_key, __u8, 65536U);
struct bpf_map_def SEC("maps") shared_scratch = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct sb_shared_scratch),
    .max_entries = 1U,
};

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __s64 (*csum_diff)(const __be32 *from, __u32 from_size, const __be32 *to, __u32 to_size, __wsum seed) =
    (void *)BPF_FUNC_csum_diff;
static long (*skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*skb_load_bytes)(const struct __sk_buff *skb, __u32 offset, void *to, __u32 length) =
    (void *)BPF_FUNC_skb_load_bytes;
static long (*l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l3_csum_replace;
static long (*l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
static long (*skb_pull_data)(struct __sk_buff *skb, __u32 length) = (void *)BPF_FUNC_skb_pull_data;
INLINE void record_shared_stat(__u32 key) {
    __u64 *counter = map_lookup(&shared_stats, &key);
    if (counter != 0) *counter += 1U;
}
INLINE void record_token_reservation_failure(void) {
    record_shared_stat(SB_SHARED_STAT_TOKEN_RESERVATION_FAILURE);
}
INLINE void record_rewrite_failure(void) {
    record_shared_stat(SB_SHARED_STAT_REWRITE_FAILURE);
}
INLINE int shared_ingress_pass(void) {
    return SB_SHARED_ACT_CONTINUE;
}
INLINE int shared_egress_pass(void) {
    return SB_SHARED_ACT_CONTINUE;
}
INLINE int shared_ingress_fragment_pass(void) {
    record_shared_stat(SB_SHARED_STAT_INGRESS_FRAGMENT_PASS);
    return SB_SHARED_ACT_CONTINUE;
}
INLINE int shared_egress_fragment_pass(void) {
    record_shared_stat(SB_SHARED_STAT_EGRESS_FRAGMENT_PASS);
    return SB_SHARED_ACT_CONTINUE;
}
INLINE void refresh_activity_timestamp(__u64 *last_seen_ns, __u64 now) {
    __u64 previous = *last_seen_ns;
    if (now >= previous &&
        now - previous >= SB_SHARED_ACTIVITY_UPDATE_INTERVAL_NS) {
        *last_seen_ns = now;
    }
}

// Host <-> network byte order. The same source is built for bpfel and bpfeb.
INLINE __u16 network_order16(__u16 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16(value);
#else
    return value;
#endif
}

INLINE __u32 network_order32(__u32 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

// Every caller copies a whole IPv6 address between 4-byte aligned fields, an
// IPv6 header address and a scratch address, so it moves words, not bytes.
INLINE void copy_address(__u8 destination[16], const __u8 source[16]) {
    __builtin_memcpy(__builtin_assume_aligned(destination, 4), __builtin_assume_aligned(source, 4), 16U);
}

SB_FORCE_LOOKUP(shared)

#include "shared_network_policy.h"

#include "shared_network_flow.h"

#include "shared_network_rewrite.h"

NOINLINE int ingress_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control,
    __u32 source_mac_first,
    __u16 source_mac_last) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return shared_ingress_pass();
    if (!selected_protocol(ip->protocol, control)) return shared_ingress_pass();
    __u16 fragment = network_order16(ip->fragment_offset);
    if ((fragment & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_FRAGMENT_MORE)) != 0U) {
        return shared_ingress_fragment_pass();
    }
    __u32 header_length = (__u32)ip->ihl * 4U;
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    __u8 protocol = ip->protocol;
    __be32 original_address = ip->destination;
    __be16 destination_port_raw = ports->destination;
    __u16 source_port = network_order16(ports->source);
    __u16 destination_port = network_order16(destination_port_raw);
    __builtin_memset(&scratch->original, 0, sizeof(scratch->original));
    scratch->original.ifindex = skb->ifindex;
    scratch->original.family = AF_INET_VALUE;
    scratch->original.protocol = protocol;
    scratch->original.client_port = source_port;
    scratch->original.original_port = destination_port;
    __builtin_memcpy(scratch->source_mac.address, &source_mac_first, 4U);
    __builtin_memcpy(scratch->source_mac.address + 4U, &source_mac_last, 2U);
    __builtin_memcpy(scratch->original.client_addr, &ip->source, 4U);
    __builtin_memcpy(scratch->original.original_addr, &ip->destination, 4U);
    if (dhcp_packet(protocol, source_port, destination_port)) {
        return shared_ingress_pass();
    }
    if (sb_ebpf_ipv4_safety_bypass((const __u8 *)&ip->destination)) {
        return shared_ingress_pass();
    }
    bool force_intercept = ((control->flags & SB_SHARED_FLAG_FORCE_INTERCEPT_IPV4) != 0U && shared_force_ipv4((const __u8 *)&ip->destination));
    __u8 port_policy = force_intercept
        ? SB_SHARED_POLICY_PROXY
        : shared_port_policy(protocol, destination_port);
    if (port_policy == SB_SHARED_POLICY_BYPASS) {
        return shared_ingress_pass();
    }
    bool respect_source = port_policy == SB_SHARED_POLICY_RESPECT_SOURCE;
    __u32 tcp_sequence = 0U;
    bool initial_syn = initial_tcp_syn(protocol, ports, data_end, &tcp_sequence);
    bool cached = load_cached_token(scratch, initial_syn);
    if (!cached && port_policy != SB_SHARED_POLICY_PROXY) {
        if (!respect_source && load_cached_bypass(scratch, control, protocol, initial_syn, tcp_sequence)) {
            return shared_ingress_pass();
        }
        if (!ipv4_client_selected(
                scratch->source_mac.address,
                (const __u8 *)&ip->source,
                control)) {
            cache_bypass(scratch, protocol, tcp_sequence);
            return shared_ingress_pass();
        }
        if (!respect_source) {
            __u8 policy = ipv4_policy(
                (const __u8 *)&ip->destination,
                protocol,
                source_port,
                destination_port,
                control);
            if (policy != SB_SHARED_POLICY_PROXY) {
                if (policy == SB_SHARED_POLICY_CACHE_BYPASS) {
                    cache_bypass(scratch, protocol, tcp_sequence);
                }
                return shared_ingress_pass();
            }
        }
    }

    // The rewrite helpers make the headers writable on demand and only need
    // the values read above, so the packet is neither pulled nor parsed again.
    if (!cached) {
        if (!reserve_token(scratch, control)) return TC_ACT_SHOT;
    }
    __be32 token_address;
    __builtin_memcpy(&token_address, scratch->token.token_addr, 4U);
    return rewrite_ipv4(
        skb,
        l3_offset,
        l3_offset + header_length,
        false,
        original_address,
        token_address,
        destination_port_raw,
        network_order16(control->listener_port),
        protocol);
}

NOINLINE int egress_ipv4(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U) return shared_egress_pass();
    if (!ipv4_token_address(ip->source, control)) return shared_egress_pass();
    if (!selected_protocol(ip->protocol, control)) return TC_ACT_SHOT;
    __u16 fragment = network_order16(ip->fragment_offset);
    if ((fragment & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_FRAGMENT_MORE)) != 0U) {
        return shared_egress_fragment_pass();
    }
    __u32 header_length = (__u32)ip->ihl * 4U;
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct transport_ports *ports = (void *)ip + header_length;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    __be16 source_port_raw = ports->source;
    if (network_order16(source_port_raw) != control->listener_port) return shared_egress_pass();
    __u8 protocol = ip->protocol;
    __be32 token_address = ip->source;

    __builtin_memset(&scratch->listener_key, 0, sizeof(scratch->listener_key));
    scratch->listener_key.family = AF_INET_VALUE;
    scratch->listener_key.protocol = protocol;
    scratch->listener_key.client_port = network_order16(ports->destination);
    scratch->listener_key.listener_port = control->listener_port;
    __builtin_memcpy(scratch->listener_key.client_addr, &ip->destination, 4U);
    __builtin_memcpy(scratch->listener_key.token_addr, &token_address, 4U);
    struct sb_shared_original_value *original = map_lookup(
        &shared_flow_by_token,
        &scratch->listener_key);
    if (original == 0 || original->ifindex != skb->ifindex) {
        return TC_ACT_SHOT;
    }
    __builtin_memcpy(&scratch->original_value, original, sizeof(scratch->original_value));
    __be32 original_address;
    __builtin_memcpy(&original_address, scratch->original_value.addr, 4U);
    return rewrite_ipv4(
        skb,
        l3_offset,
        l3_offset + header_length,
        true,
        token_address,
        original_address,
        source_port_raw,
        network_order16(scratch->original_value.port),
        protocol);
}

NOINLINE __u64 ipv6_transport_offset(
    void *data,
    void *data_end,
    __u32 l3_offset,
    __u8 *protocol_out) {
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end) return IPV6_TRANSPORT_DROP;
    __u8 protocol = ip->next_header;
    __u32 offset = l3_offset + sizeof(*ip);
    __u64 result = 0U;
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (result != 0U) continue;
        if (protocol == IPPROTO_TCP_VALUE || protocol == IPPROTO_UDP_VALUE) {
            *protocol_out = protocol;
            result = offset;
        } else if (protocol == 44U) {
            struct ipv6_fragment_header *fragment = data + offset;
            if ((void *)(fragment + 1) > data_end) {
                result = IPV6_TRANSPORT_DROP;
                continue;
            }
            protocol = fragment->next_header;
            __u16 fragment_offset = network_order16(fragment->fragment_offset);
            if ((fragment_offset & (IPV6_FRAGMENT_OFFSET_MASK | IPV6_FRAGMENT_MORE)) != 0U) {
                result = IPV6_TRANSPORT_FRAGMENT;
                continue;
            }
            if (protocol != IPPROTO_TCP_VALUE && protocol != IPPROTO_UDP_VALUE) {
                if (protocol == 0U || protocol == 43U || protocol == 60U ||
                    protocol == 51U || protocol == 44U) {
                    result = IPV6_TRANSPORT_DROP;
                } else {
                    result = IPV6_TRANSPORT_BYPASS;
                }
                continue;
            }
            offset += sizeof(*fragment);
            *protocol_out = protocol;
            result = offset;
        } else if (protocol != 0U && protocol != 43U && protocol != 60U && protocol != 51U) {
            result = IPV6_TRANSPORT_BYPASS;
        } else {
            struct ipv6_extension_header *extension = data + offset;
            if ((void *)(extension + 1) > data_end) {
                result = IPV6_TRANSPORT_DROP;
                continue;
            }
            __u8 current = protocol;
            protocol = extension->next_header;
            offset += current == 51U
                ? ((__u32)extension->length + 2U) * 4U
                : ((__u32)extension->length + 1U) * 8U;
            if (data + offset > data_end) result = IPV6_TRANSPORT_DROP;
        }
    }
    return result == 0U ? IPV6_TRANSPORT_DROP : result;
}

NOINLINE int ingress_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control,
    __u32 source_mac_first,
    __u16 source_mac_last) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (network_order32(ip->version_flow) >> 28U) != 6U) return shared_ingress_pass();
    __u8 protocol = 0U;
    __u64 transport_result = ipv6_transport_offset(
        data,
        data_end,
        l3_offset,
        &protocol);
    __u32 transport = (__u32)transport_result;
    if (transport == IPV6_TRANSPORT_DROP) return TC_ACT_SHOT;
    if (transport == IPV6_TRANSPORT_BYPASS) return shared_ingress_pass();
    if (transport == IPV6_TRANSPORT_FRAGMENT) return shared_ingress_fragment_pass();
    if ((transport & IPV6_TRANSPORT_MASK) < IPV6_TRANSPORT_MIN_OFFSET ||
        (transport & IPV6_TRANSPORT_MASK) > IPV6_TRANSPORT_MAX_OFFSET) {
        return TC_ACT_SHOT;
    }
    transport &= IPV6_TRANSPORT_MASK;
    if (!selected_protocol(protocol, control)) return shared_ingress_pass();
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct transport_ports *ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    __be16 source_port_raw = ports->source;
    __be16 destination_port_raw = ports->destination;
    __u16 source_port = network_order16(source_port_raw);
    __u16 destination_port = network_order16(destination_port_raw);
    __builtin_memset(&scratch->original, 0, sizeof(scratch->original));
    scratch->original.ifindex = skb->ifindex;
    scratch->original.family = AF_INET6_VALUE;
    scratch->original.protocol = protocol;
    scratch->original.client_port = source_port;
    scratch->original.original_port = destination_port;
    __builtin_memcpy(scratch->source_mac.address, &source_mac_first, 4U);
    __builtin_memcpy(scratch->source_mac.address + 4U, &source_mac_last, 2U);
    copy_address(scratch->original.client_addr, ip->source);
    copy_address(scratch->original.original_addr, ip->destination);
    if (dhcp_packet(protocol, source_port, destination_port)) {
        return shared_ingress_pass();
    }
    if (sb_ebpf_ipv6_safety_bypass(ip->destination)) {
        return shared_ingress_pass();
    }
    bool force_intercept = ((control->flags & SB_SHARED_FLAG_FORCE_INTERCEPT_IPV6) != 0U && shared_force_ipv6(ip->destination));
    __u8 port_policy = force_intercept
        ? SB_SHARED_POLICY_PROXY
        : shared_port_policy(protocol, destination_port);
    if (port_policy == SB_SHARED_POLICY_BYPASS) {
        return shared_ingress_pass();
    }
    bool respect_source = port_policy == SB_SHARED_POLICY_RESPECT_SOURCE;
    __u32 tcp_sequence = 0U;
    bool initial_syn = initial_tcp_syn(protocol, ports, data_end, &tcp_sequence);
    bool cached = load_cached_token(scratch, initial_syn);
    if (!cached && port_policy != SB_SHARED_POLICY_PROXY) {
        if (!respect_source && load_cached_bypass(scratch, control, protocol, initial_syn, tcp_sequence)) {
            return shared_ingress_pass();
        }
        if (!ipv6_client_selected(scratch->source_mac.address, ip->source, control)) {
            cache_bypass(scratch, protocol, tcp_sequence);
            return shared_ingress_pass();
        }
        if (!respect_source) {
            __u8 policy = ipv6_policy(
                ip->destination,
                protocol,
                source_port,
                destination_port,
                control);
            if (policy != SB_SHARED_POLICY_PROXY) {
                if (policy == SB_SHARED_POLICY_CACHE_BYPASS) {
                    cache_bypass(scratch, protocol, tcp_sequence);
                }
                return shared_ingress_pass();
            }
        }
    }

    // The rewrite helpers make the headers writable on demand and only need
    // the values read above, so the packet is neither pulled nor parsed again.
    // The transport offset goes through scratch memory: its extension-header
    // dependent bounds would otherwise make the verifier walk reserve_token
    // once per header layout, which exceeds the Linux 4.19 complexity limit.
    scratch->transport_offset = transport;
    if (!cached) {
        if (!reserve_token(scratch, control)) return TC_ACT_SHOT;
    }
    return rewrite_ipv6(
        skb,
        l3_offset,
        scratch->transport_offset,
        false,
        scratch->original.original_addr,
        scratch->token.token_addr,
        destination_port_raw,
        network_order16(control->listener_port),
        protocol);
}

NOINLINE int egress_ipv6(
    struct __sk_buff *skb,
    __u32 l3_offset,
    const struct sb_shared_control *control) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (network_order32(ip->version_flow) >> 28U) != 6U) return shared_egress_pass();
    if (!ipv6_token_address(ip->source, control)) return shared_egress_pass();
    __u8 protocol = 0U;
    __u64 transport_result = ipv6_transport_offset(
        data,
        data_end,
        l3_offset,
        &protocol);
    __u32 transport = (__u32)transport_result;
    if (transport == IPV6_TRANSPORT_BYPASS) return TC_ACT_SHOT;
    if (transport == IPV6_TRANSPORT_FRAGMENT) return shared_egress_fragment_pass();
    if ((transport & IPV6_TRANSPORT_MASK) < IPV6_TRANSPORT_MIN_OFFSET ||
        (transport & IPV6_TRANSPORT_MASK) > IPV6_TRANSPORT_MAX_OFFSET) {
        return TC_ACT_SHOT;
    }
    transport &= IPV6_TRANSPORT_MASK;
    if (!selected_protocol(protocol, control)) return TC_ACT_SHOT;
    __u32 zero = 0U;
    struct sb_shared_scratch *scratch = map_lookup(&shared_scratch, &zero);
    if (scratch == 0) return TC_ACT_SHOT;
    struct transport_ports *ports = data + transport;
    if ((void *)(ports + 1) > data_end) return TC_ACT_SHOT;
    __be16 source_port_raw = ports->source;
    if (network_order16(source_port_raw) != control->listener_port) return shared_egress_pass();
    __be16 destination_port_raw = ports->destination;

    __builtin_memset(&scratch->listener_key, 0, sizeof(scratch->listener_key));
    scratch->listener_key.family = AF_INET6_VALUE;
    scratch->listener_key.protocol = protocol;
    scratch->listener_key.client_port = network_order16(destination_port_raw);
    scratch->listener_key.listener_port = control->listener_port;
    copy_address(scratch->listener_key.client_addr, ip->destination);
    copy_address(scratch->listener_key.token_addr, ip->source);
    struct sb_shared_original_value *original = map_lookup(
        &shared_flow_by_token,
        &scratch->listener_key);
    if (original == 0 || original->ifindex != skb->ifindex) {
        return TC_ACT_SHOT;
    }
    __builtin_memcpy(&scratch->original_value, original, sizeof(scratch->original_value));
    return rewrite_ipv6(
        skb,
        l3_offset,
        transport,
        true,
        scratch->listener_key.token_addr,
        scratch->original_value.addr,
        source_port_raw,
        network_order16(scratch->original_value.port),
        protocol);
}

// Drivers that build received packets in page fragments (napi_gro_frags users
// such as mlx4, sfc and gve, or any device with GRO off) can leave headers GRO
// did not parse, such as a UDP header, outside the linear area that direct
// packet access reads; ingress would then drop the packet as truncated. The
// pull covers the longest header layout parsed before the transport ports and
// happens before anything is parsed: a packet value kept across the helper
// call loses its bounds on verifiers before Linux 5.10, which then walk the
// rewrite path once per side of the pull and exceed the 4.19 complexity limit.
// A packet whose first bytes are linear, including every short linear packet,
// only pays the compare.
#define SB_SHARED_PULL_LENGTH (sizeof(struct ethernet_header) + 2U * sizeof(struct vlan_header) + \
    sizeof(struct ipv6_header) + sizeof(struct udp_header_min))

// Volatile so that both sides of the pull load the pointers again after it
// and reach the parser in the same verifier state.
#define SKB_DATA(skb) ((void *)(long)*(volatile __u32 *)&(skb)->data)
#define SKB_DATA_END(skb) ((void *)(long)*(volatile __u32 *)&(skb)->data_end)

INLINE void pull_headers(struct __sk_buff *skb, __u32 length) {
    __u32 available = skb->len;
    if (available < length) length = available;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + length <= data_end) return;
    (void)skb_pull_data(skb, length);
}

NOINLINE int classify_ingress(struct __sk_buff *skb) {
    __u32 zero = 0U;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (control == 0 || control->enabled == 0U) return shared_ingress_pass();
    pull_headers(skb, SB_SHARED_PULL_LENGTH);
    void *data = SKB_DATA(skb);
    void *data_end = SKB_DATA_END(skb);
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return shared_ingress_pass();
    __u16 protocol = network_order16(ethernet->protocol);
    __u32 l3_offset = sizeof(*ethernet);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (protocol != ETH_P_8021Q_VALUE && protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + l3_offset;
        if ((void *)(vlan + 1) > data_end) return shared_ingress_pass();
        protocol = network_order16(vlan->protocol);
        l3_offset += sizeof(*vlan);
    }
    __u32 source_mac_first;
    __u16 source_mac_last;
    __builtin_memcpy(&source_mac_first, ethernet->source, 4U);
    __builtin_memcpy(&source_mac_last, ethernet->source + 4U, 2U);
    if (protocol == ETH_P_IP_VALUE && (control->flags & SB_SHARED_FLAG_IPV4) != 0U) {
        return ingress_ipv4(skb, l3_offset, control, source_mac_first, source_mac_last);
    }
    if (protocol == ETH_P_IPV6_VALUE && (control->flags & SB_SHARED_FLAG_IPV6) != 0U) {
        return ingress_ipv6(skb, l3_offset, control, source_mac_first, source_mac_last);
    }
    return shared_ingress_pass();
}

NOINLINE int classify_egress(struct __sk_buff *skb) {
    __u32 zero = 0U;
    struct sb_shared_control *control = map_lookup(&shared_control, &zero);
    if (control == 0 || control->enabled == 0U) return shared_egress_pass();
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return shared_egress_pass();
    __u16 protocol = network_order16(ethernet->protocol);
    __u32 l3_offset = sizeof(*ethernet);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (protocol != ETH_P_8021Q_VALUE && protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + l3_offset;
        if ((void *)(vlan + 1) > data_end) return shared_egress_pass();
        protocol = network_order16(vlan->protocol);
        l3_offset += sizeof(*vlan);
    }
    if (protocol == ETH_P_IP_VALUE && (control->flags & SB_SHARED_FLAG_IPV4) != 0U) {
        return egress_ipv4(skb, l3_offset, control);
    }
    if (protocol == ETH_P_IPV6_VALUE && (control->flags & SB_SHARED_FLAG_IPV6) != 0U) {
        return egress_ipv6(skb, l3_offset, control);
    }
    return shared_egress_pass();
}


SEC("classifier/ingress")
int sing_ebpf_shared_ingress(struct __sk_buff *skb) {
    return classify_ingress(skb);
}

SEC("classifier/egress")
int sing_ebpf_shared_egress(struct __sk_buff *skb) {
    return classify_egress(skb);
}

char _license[] SEC("license") = "GPL";
