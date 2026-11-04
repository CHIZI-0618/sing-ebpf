// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_EBPF_SHARED_NETWORK_FLOW_H
#define SING_EBPF_SHARED_NETWORK_FLOW_H

// Scratch and control fields copied or hashed below are 4-byte aligned, so
// they can be accessed as words instead of byte by byte.
#define SB_ALIGNED4(pointer) __builtin_assume_aligned((pointer), 4)

INLINE __u32 mix32(__u32 value) {
    value ^= value >> 16U;
    value *= 0x7feb352dU;
    value ^= value >> 15U;
    value *= 0x846ca68bU;
    return value ^ (value >> 16U);
}

// hash_original returns two independently seeded hashes of the flow key, one
// per 32-bit half, from a single word-wise pass. Tokens only need to spread
// across the prefix: the no-exist inserts resolve collisions.
NOINLINE __u64 hash_original(const struct sb_shared_original_key *key, __u32 salt) {
    __u32 first = 2166136261U ^ salt;
    __u32 second = 0x85ebca6bU ^ salt;
#pragma clang loop unroll(full)
    for (__u32 offset = 0U; offset < sizeof(*key); offset += sizeof(__u32)) {
        __u32 word;
        __builtin_memcpy(&word, (const __u8 *)SB_ALIGNED4(key) + offset, sizeof(word));
        first = (first ^ word) * 16777619U;
        first ^= first >> 15U;
        second = (second ^ word) * 0x9e3779b1U;
        second ^= second >> 13U;
    }
    return ((__u64)mix32(first) << 32U) | mix32(second);
}

INLINE void copy_scratch_address(__u8 destination[16], const __u8 source[16], bool ipv6) {
    __builtin_memcpy(SB_ALIGNED4(destination), SB_ALIGNED4(source), 4U);
    if (ipv6) __builtin_memcpy(SB_ALIGNED4(destination + 4U), SB_ALIGNED4(source + 4U), 12U);
}

INLINE void fill_listener(struct sb_shared_scratch *scratch, const struct sb_shared_control *control) {
    __builtin_memset(&scratch->listener_key, 0, sizeof(scratch->listener_key));
    scratch->listener_key.family = scratch->original.family;
    scratch->listener_key.protocol = scratch->original.protocol;
    scratch->listener_key.listener_port = control->listener_port;
    scratch->listener_key.client_port = scratch->original.client_port;
    bool ipv6 = scratch->original.family == AF_INET6_VALUE;
    copy_scratch_address(scratch->listener_key.token_addr, scratch->token.token_addr, ipv6);
    copy_scratch_address(scratch->listener_key.client_addr, scratch->original.client_addr, ipv6);
    __builtin_memset(&scratch->original_value, 0, sizeof(scratch->original_value));
    scratch->original_value.family = scratch->original.family;
    scratch->original_value.protocol = scratch->original.protocol;
    scratch->original_value.port = scratch->original.original_port;
    scratch->original_value.ifindex = scratch->original.ifindex;
    scratch->original_value.generation = scratch->token.generation;
    __builtin_memcpy(scratch->original_value.source_mac, scratch->source_mac.address, 6U);
    copy_scratch_address(scratch->original_value.addr, scratch->original.original_addr, ipv6);
}

NOINLINE bool publish_token(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u64 listener_flags) {
    fill_listener(scratch, control);
    return map_update(
        &shared_flow_by_token,
        &scratch->listener_key,
        &scratch->original_value,
        listener_flags) == 0;
}

INLINE void delete_token_generation(struct sb_shared_scratch *scratch) {
    struct sb_shared_original_value *reverse = map_lookup(
        &shared_flow_by_token,
        &scratch->listener_key);
    if (reverse != 0 && reverse->generation == scratch->token.generation) {
        map_delete(&shared_flow_by_token, &scratch->listener_key);
    }
}

#define SB_SHARED_TOKEN_RETRY 0
#define SB_SHARED_TOKEN_RESERVED 1

// Keep each attempt in its own BPF subprogram: LLVM 21 otherwise carries loop
// state in caller-clobbered registers across the map subprogram calls.
NOINLINE int reserve_token_attempt(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u32 hash,
    __u32 second,
    __u64 now) {
    __builtin_memset(&scratch->token, 0, sizeof(scratch->token));
    if (scratch->original.family == AF_INET_VALUE) {
        __u32 prefix = ((__u32)control->token_ipv4_prefix[0] << 24U) |
            ((__u32)control->token_ipv4_prefix[1] << 16U) |
            ((__u32)control->token_ipv4_prefix[2] << 8U) |
            (__u32)control->token_ipv4_prefix[3];
        __u32 host_bits = 32U - (__u32)control->token_ipv4_prefix_bits;
        __u32 host_mask = 0xffffffffU >> (32U - host_bits);
        __u32 candidate = (prefix & ~host_mask) | (hash & host_mask);
        if ((candidate & host_mask) == 0U || (candidate & host_mask) == host_mask) {
            return SB_SHARED_TOKEN_RETRY;
        }
        scratch->token.token_addr[0] = (__u8)(candidate >> 24U);
        scratch->token.token_addr[1] = (__u8)(candidate >> 16U);
        scratch->token.token_addr[2] = (__u8)(candidate >> 8U);
        scratch->token.token_addr[3] = (__u8)candidate;
    } else {
        __builtin_memcpy(SB_ALIGNED4(scratch->token.token_addr), SB_ALIGNED4(control->token_ipv6_prefix), 8U);
        scratch->token.token_addr[8] = (__u8)(hash >> 24U);
        scratch->token.token_addr[9] = (__u8)(hash >> 16U);
        scratch->token.token_addr[10] = (__u8)(hash >> 8U);
        scratch->token.token_addr[11] = (__u8)hash;
        scratch->token.token_addr[12] = (__u8)(second >> 24U);
        scratch->token.token_addr[13] = (__u8)(second >> 16U);
        scratch->token.token_addr[14] = (__u8)(second >> 8U);
        scratch->token.token_addr[15] = (__u8)second;
    }
    scratch->token.generation = now ^ ((__u64)hash << 32U);
    scratch->token.last_seen_ns = now;
    if (!publish_token(scratch, control, BPF_NOEXIST)) {
        return SB_SHARED_TOKEN_RETRY;
    }
    if (map_update(
            &shared_flow_by_original,
            &scratch->original,
            &scratch->token,
            BPF_NOEXIST) == 0) {
        return SB_SHARED_TOKEN_RESERVED;
    }
    delete_token_generation(scratch);
    struct sb_shared_token_value *existing = map_lookup(
        &shared_flow_by_original,
        &scratch->original);
    if (existing != 0) {
        __builtin_memcpy(&scratch->token, existing, sizeof(scratch->token));
        return SB_SHARED_TOKEN_RESERVED;
    }
    return SB_SHARED_TOKEN_RETRY;
}

// The flow is hashed once per reservation and each attempt derives its own
// candidate. Hashing inside every attempt multiplied the verifier's work by
// the attempt count and put the ingress program over the Linux 4.19
// complexity limit.
NOINLINE bool reserve_token(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control) {
    __u64 now = ktime_get_ns();
    __u64 hashes = hash_original(&scratch->original, (__u32)now ^ (__u32)(now >> 32U));
    __u32 hash = (__u32)(hashes >> 32U);
    __u32 second = (__u32)hashes;
    int result = SB_SHARED_TOKEN_RETRY;
#pragma clang loop unroll(full)
    for (__u32 attempt = 0U; attempt < SB_SHARED_TOKEN_ATTEMPTS; ++attempt) {
        if (result == SB_SHARED_TOKEN_RETRY) {
            result = reserve_token_attempt(
                scratch,
                control,
                mix32(hash + 0x9e3779b9U * (attempt + 1U)),
                mix32(second + 0x7f4a7c15U * (attempt + 1U)),
                now);
        }
    }
    if (result != SB_SHARED_TOKEN_RESERVED) record_token_reservation_failure();
    return result == SB_SHARED_TOKEN_RESERVED;
}

// TCP traffic does not refresh a flow's activity time, so a TCP flow's
// last_seen_ns only moves when an initial SYN reuses it: a client opening a
// new connection from the tuple of one that just closed. Userspace compares it
// with the time it released the flow, so the delayed release of the closed
// connection does not delete the flow the new connection now uses.
INLINE bool load_cached_token(struct sb_shared_scratch *scratch, bool initial_syn) {
    struct sb_shared_token_value *existing = map_lookup(
        &shared_flow_by_original,
        &scratch->original);
    if (existing == 0) return false;
    if (scratch->original.protocol != IPPROTO_TCP_VALUE) {
        refresh_activity_timestamp(&existing->last_seen_ns, ktime_get_ns());
    } else if (initial_syn) {
        existing->last_seen_ns = ktime_get_ns();
    }
    __builtin_memcpy(&scratch->token, existing, sizeof(scratch->token));
    return true;
}

INLINE bool initial_tcp_syn(
    __u8 protocol,
    const struct transport_ports *ports,
    const void *data_end,
    __u32 *sequence) {
    if (protocol != IPPROTO_TCP_VALUE) return false;
    const struct tcp_header_min *tcp = (const void *)ports;
    if ((const void *)(tcp + 1) > data_end) return false;
    __u16 flags = network_order16(tcp->flags);
    if ((flags & TCP_FLAG_SYN) == 0U || (flags & TCP_FLAG_ACK) != 0U) return false;
    *sequence = tcp->sequence;
    return true;
}

NOINLINE bool load_cached_bypass(
    struct sb_shared_scratch *scratch,
    const struct sb_shared_control *control,
    __u8 protocol,
    bool initial_syn,
    __u32 tcp_sequence) {
    if ((control->flags & SB_SHARED_FLAG_BYPASS_FLOW_CACHE) == 0U) return false;
    struct sb_shared_bypass_flow_value *cached = map_lookup(
        &shared_bypass_flow,
        &scratch->original);
    if (cached == 0) return false;
    if (protocol == IPPROTO_TCP_VALUE) {
        if (!initial_syn || cached->tcp_sequence == tcp_sequence) return true;
        map_delete(&shared_bypass_flow, &scratch->original);
        return false;
    }
    __u64 now = ktime_get_ns();
    __u64 timeout = (__u64)control->udp_timeout_seconds * 1000000000ULL;
    if (now - cached->last_seen_ns > timeout) {
        map_delete(&shared_bypass_flow, &scratch->original);
        return false;
    }
    refresh_activity_timestamp(&cached->last_seen_ns, now);
    return true;
}

NOINLINE void cache_bypass(
    struct sb_shared_scratch *scratch,
    __u8 protocol,
    __u32 tcp_sequence) {
    __builtin_memset(&scratch->bypass_flow, 0, sizeof(scratch->bypass_flow));
    scratch->bypass_flow.last_seen_ns = ktime_get_ns();
    if (protocol == IPPROTO_TCP_VALUE) scratch->bypass_flow.tcp_sequence = tcp_sequence;
    map_update(
        &shared_bypass_flow,
        &scratch->original,
        &scratch->bypass_flow,
        BPF_ANY);
}

#endif
