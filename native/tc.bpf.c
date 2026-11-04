// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "abi.h"
#include "bpf_compat.h"
#include "force_intercept_policy.h"
#include "private_address.h"

#include <linux/bpf.h>

#define BPF_ANY 0U
#define BPF_F_CURRENT_NETNS (-1ULL)
#define BPF_F_INGRESS (1ULL << 0)
#define BPF_TCP_LISTEN 10U
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC (-1)

#define ETH_P_IP_VALUE 0x0800U
#define ETH_P_IPV6_VALUE 0x86ddU
#define ETH_P_8021Q_VALUE 0x8100U
#define ETH_P_8021AD_VALUE 0x88a8U
#define AF_INET_VALUE 2U
#define AF_INET6_VALUE 10U
#define IPPROTO_TCP_VALUE 6U
#define IPPROTO_UDP_VALUE 17U
#define IPPROTO_HOPOPTS_VALUE 0U
#define IPPROTO_ROUTING_VALUE 43U
#define IPPROTO_FRAGMENT_VALUE 44U
#define IPPROTO_AH_VALUE 51U
#define IPPROTO_DSTOPTS_VALUE 60U
#define IPV4_FRAGMENT_OFFSET_MASK 0x1fffU
#define IPV4_FRAGMENT_MORE 0x2000U
#define IPV6_FRAGMENT_OFFSET_MASK 0xfff8U
#define IPV6_FRAGMENT_MORE 0x0001U
#define TCP_FLAG_SYN 0x02U
#define TCP_FLAGS_OFFSET 13U

#define SB_TC_FLAG_IPV4 (1U << 0)
#define SB_TC_FLAG_LOCAL_IPV6 (1U << 1)
#define SB_TC_FLAG_TCP (1U << 2)
#define SB_TC_FLAG_UDP (1U << 3)
#define SB_TC_FLAG_UID_POLICY (1U << 4)
#define SB_TC_FLAG_UID_DEFAULT_BYPASS (1U << 5)
#define SB_TC_FLAG_SHARED_DEFAULT_BYPASS (1U << 7)
#define SB_TC_FLAG_BYPASS_IPV4 (1U << 8)
#define SB_TC_FLAG_BYPASS_IPV6 (1U << 9)
#define SB_TC_FLAG_LOCAL_BYPASS_IPV4 SB_TC_FLAG_BYPASS_IPV4
#define SB_TC_FLAG_LOCAL_BYPASS_IPV6 SB_TC_FLAG_BYPASS_IPV6
#define SB_TC_FLAG_FORCE_INTERCEPT_IPV4 (1U << 10)
#define SB_TC_FLAG_FORCE_INTERCEPT_IPV6 (1U << 11)
#define SB_TC_FLAG_INCLUDE_SOURCE (1U << 12)
#define SB_TC_FLAG_EXCLUDE_SOURCE (1U << 13)
#define SB_TC_FLAG_INCLUDE_SOURCE_MAC (1U << 14)
#define SB_TC_FLAG_EXCLUDE_SOURCE_MAC (1U << 15)
#define SB_TC_FLAG_HOST_IPV4 (1U << 16)
#define SB_TC_FLAG_HOST_IPV6 (1U << 17)
#define SB_TC_FLAG_SHARED_IPV6 (1U << 18)
#define SB_TC_FLAG_LOCAL_BYPASS_PORT (1U << 20)
#define SB_TC_FLAG_SHARED_BYPASS_PORT (1U << 21)
#define SB_TC_FLAG_SHARED_BYPASS_IPV4 (1U << 22)
#define SB_TC_FLAG_SHARED_BYPASS_IPV6 (1U << 23)

#define SB_TC_SOCKET_POLICY_BYPASS 1U
#define SB_TC_SOCKET_POLICY_INTERCEPT 2U


#define SB_TC_LISTENER_TCP4 0U
#define SB_TC_LISTENER_TCP6 1U
#define SB_TC_LISTENER_COUNT 2U

#define SB_TC_PATH_SHARED 1U
#define SB_TC_PATH_DELIVERY 2U
#define SB_TC_PATH_SOURCE_MAC_VALID 0x80U

#define SB_TC_STAT_SOCKET_LOOKUP_FAILURE 0U
#define SB_TC_STAT_SK_ASSIGN_FAILURE 1U
#define SB_TC_STAT_ASSIGNMENT_UPDATE_FAILURE 2U
#define SB_TC_STAT_LOCAL_FRAGMENT_PASS 3U
#define SB_TC_STAT_SHARED_FRAGMENT_PASS 4U
#define SB_TC_STAT_RETURN_UPDATE_FAILURE 5U
#define SB_TC_STAT_RETURN_CONFLICT 6U
#define SB_TC_STAT_RETURN_LOOKUP_FAILURE 7U
#define SB_TC_STAT_COUNT 8U

struct sb_tc_control {
    __u32 enabled;
    __u32 flags;
    __u32 delivery_ifindex;
    __u32 routing_mark;
    __u16 listener_port;
    __u16 reserved_policy[2];
    __u8 delivery_mac[6];
    __u16 reserved;
};

struct sb_tc_uid_key {
    __u32 prefixlen;
    __u8 uid[4];
};

struct sb_tc_ipv4_lpm_key {
    __u32 prefixlen;
    __u8 address[4];
};

struct sb_tc_ipv6_lpm_key {
    __u32 prefixlen;
    __u8 address[16];
};

struct sb_tc_ipv4_key {
    __u8 address[4];
};

struct sb_tc_ipv6_key {
    __u8 address[16];
};

struct sb_tc_mac_key {
    __u8 address[6];
    __u8 reserved[2];
};

struct sb_tc_port_key {
    __u8 protocol;
    __u8 reserved;
    __u16 port;
};

struct sb_tc_assign_key {
    __u8 family;
    __u8 protocol;
    __u16 source_port;
    __u16 destination_port;
    __u16 reserved;
    __u32 interface_index;
    __u8 source_addr[16];
    __u8 destination_addr[16];
};

struct sb_tc_assign_value {
    __u64 socket_cookie;
    __u64 last_seen_ns;
    __u32 ifindex;
    __u8 source_mac[6];
    __u8 path;
    __u8 source_mac_valid;
    __u32 generation;
};

_Static_assert(sizeof(struct sb_tc_control) == 32, "sb_tc_control ABI size");
_Static_assert(__builtin_offsetof(struct sb_tc_control, delivery_ifindex) == 8,
    "sb_tc_control delivery_ifindex ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, routing_mark) == 12,
    "sb_tc_control routing_mark ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_control, listener_port) == 16,
    "sb_tc_control listener_port ABI offset");
_Static_assert(sizeof(struct sb_tc_assign_key) == 44, "sb_tc_assign_key ABI size");
_Static_assert(sizeof(struct sb_tc_assign_value) == 32, "sb_tc_assign_value ABI size");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, socket_cookie) == 0,
    "sb_tc_assign_value socket_cookie ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, last_seen_ns) == 8,
    "sb_tc_assign_value last_seen_ns ABI offset");
_Static_assert(__builtin_offsetof(struct sb_tc_assign_value, generation) == 28,
    "sb_tc_assign_value generation ABI offset");

struct ethernet_header {
    __u8 destination[6];
    __u8 source[6];
    __be16 protocol;
};

struct vlan_header {
    __be16 tci;
    __be16 protocol;
};

struct ipv4_header {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __be16 total_length;
    __be16 id;
    __be16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __sum16 checksum;
    __be32 source;
    __be32 destination;
};

struct ipv6_header {
    __be32 version_flow;
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 source[16];
    __u8 destination[16];
};

struct transport_ports {
    __be16 source;
    __be16 destination;
};

struct ipv6_extension_header {
    __u8 next_header;
    __u8 length;
};

struct ipv6_fragment_header {
    __u8 next_header;
    __u8 reserved;
    __be16 offset_flags;
    __be32 identification;
};

#define MAP(name, key, value, map_type, entries) \
    struct bpf_map_def SEC("maps") name = { \
        .type = map_type, .key_size = sizeof(key), .value_size = sizeof(value), \
        .max_entries = entries, \
    }

MAP(tc_control, __u32, struct sb_tc_control, BPF_MAP_TYPE_ARRAY, 1U);
MAP(tc_listener_sockets, __u32, __u32, BPF_MAP_TYPE_SOCKMAP, SB_TC_LISTENER_COUNT);
MAP(tc_assignment, struct sb_tc_assign_key, struct sb_tc_assign_value, BPF_MAP_TYPE_LRU_HASH, 65536U);
MAP(tc_stats, __u32, __u64, BPF_MAP_TYPE_PERCPU_ARRAY, SB_TC_STAT_COUNT);
MAP(tc_self_sockets, __u64, __u32, BPF_MAP_TYPE_LRU_HASH, 65536U);
MAP(tc_uid_policy, struct sb_tc_uid_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_local_bypass_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_local_bypass_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_shared_bypass_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_shared_bypass_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 65536U);
MAP(tc_include_source_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_include_source_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_exclude_source_ipv4, struct sb_tc_ipv4_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_exclude_source_ipv6, struct sb_tc_ipv6_lpm_key, __u8, BPF_MAP_TYPE_LPM_TRIE, 4096U);
MAP(tc_include_source_mac, struct sb_tc_mac_key, __u8, BPF_MAP_TYPE_HASH, 1024U);
MAP(tc_exclude_source_mac, struct sb_tc_mac_key, __u8, BPF_MAP_TYPE_HASH, 1024U);
MAP(tc_host_ipv4, struct sb_tc_ipv4_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_host_ipv6, struct sb_tc_ipv6_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
SB_FORCE_MAPS(tc_local);
SB_FORCE_MAPS(tc_shared);

MAP(tc_local_bypass_port, struct sb_tc_port_key, __u8, BPF_MAP_TYPE_HASH, 4096U);
MAP(tc_shared_bypass_port, struct sb_tc_port_key, __u8, BPF_MAP_TYPE_HASH, 4096U);

static void *(*map_lookup)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *map, const void *key, const void *value, __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*map_delete)(void *map, const void *key) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;

static __u32 next_assignment_generation(const struct sb_tc_assign_value *existing) {
    if (existing == 0 || existing->generation == 0U || existing->generation == 0xffffffffU) return 1U;
    return existing->generation + 1U;
}
static __u32 (*get_socket_uid)(void *ctx) = (void *)BPF_FUNC_get_socket_uid;
static __u64 (*get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static long (*redirect)(int ifindex, __u64 flags) = (void *)BPF_FUNC_redirect;
static long (*skb_store_bytes)(void *ctx, __u32 offset, const void *from, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*skb_change_head)(void *ctx, __u32 length, __u64 flags) =
    (void *)BPF_FUNC_skb_change_head;
static struct bpf_sock *(*skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple,
    __u32 tuple_size, __u64 netns, __u64 flags) = (void *)BPF_FUNC_skc_lookup_tcp;
static struct bpf_sock *(*sk_lookup_udp)(void *ctx, struct bpf_sock_tuple *tuple,
    __u32 tuple_size, __u64 netns, __u64 flags) = (void *)BPF_FUNC_sk_lookup_udp;
static long (*skb_pull_data)(void *ctx, __u32 length) = (void *)BPF_FUNC_skb_pull_data;
static long (*sk_assign)(void *ctx, struct bpf_sock *socket, __u64 flags) =
    (void *)BPF_FUNC_sk_assign;
static void (*sk_release)(struct bpf_sock *socket) = (void *)BPF_FUNC_sk_release;

INLINE void increment_stat(__u32 index) {
    if (index >= SB_TC_STAT_COUNT) return;
    __u64 *value = map_lookup(&tc_stats, &index);
    if (value != 0) *value += 1U;
}

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

// Every caller copies a whole IPv6 address between 4-byte aligned fields: an
// IPv6 header address, an assignment key address or a bpf_sock_tuple address.
// Word moves replace the 16 byte loads and stores per address.
INLINE void copy_address(__u8 destination[16], const __u8 source[16]) {
    __builtin_memcpy(__builtin_assume_aligned(destination, 4), __builtin_assume_aligned(source, 4), 16U);
}

INLINE const struct sb_tc_control *load_control(void) {
    __u32 zero = 0U;
    return map_lookup(&tc_control, &zero);
}

INLINE bool protocol_enabled(const struct sb_tc_control *control, __u8 protocol) {
    if (protocol == IPPROTO_TCP_VALUE) return (control->flags & SB_TC_FLAG_TCP) != 0U;
    if (protocol == IPPROTO_UDP_VALUE) return (control->flags & SB_TC_FLAG_UDP) != 0U;
    return false;
}

INLINE bool service_port(__u8 protocol, __u16 source, __u16 destination) {
    if (protocol != IPPROTO_UDP_VALUE) return false;
    return source == 67U || source == 68U || source == 546U || source == 547U ||
        destination == 67U || destination == 68U || destination == 546U || destination == 547U;
}

SB_FORCE_LOOKUP(tc_local)
SB_FORCE_LOOKUP(tc_shared)

INLINE bool uid_bypassed(struct __sk_buff *skb, const struct sb_tc_control *control) {
    if ((control->flags & SB_TC_FLAG_UID_POLICY) == 0U) return false;
    __u32 uid = network_order32(get_socket_uid(skb));
    struct sb_tc_uid_key key = {.prefixlen = 32U};
    __builtin_memcpy(key.uid, &uid, sizeof(uid));
    bool matched = map_lookup(&tc_uid_policy, &key) != 0;
    return (control->flags & SB_TC_FLAG_UID_DEFAULT_BYPASS) != 0U ? !matched : matched;
}

INLINE __u32 socket_metadata(__u64 socket_cookie) {
    if (socket_cookie == 0U) return 0U;
    __u32 *metadata = map_lookup(&tc_self_sockets, &socket_cookie);
    return metadata != 0 ? *metadata : 0U;
}

INLINE __u8 port_action(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, bool shared) {
    __u32 flag = shared ? SB_TC_FLAG_SHARED_BYPASS_PORT : SB_TC_FLAG_LOCAL_BYPASS_PORT;
    if ((control->flags & flag) == 0U) return false;
    struct sb_tc_port_key key = {.protocol = flow->protocol, .port = flow->destination_port};
    __u8 *action = shared ? map_lookup(&tc_shared_bypass_port, &key) : map_lookup(&tc_local_bypass_port, &key);
    return action != 0 ? *action : 0U;
}

INLINE bool force_intercept_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, bool shared) {
    if (key->family == AF_INET_VALUE) {
        if ((control->flags & SB_TC_FLAG_FORCE_INTERCEPT_IPV4) == 0U) return false;
        return shared ? tc_shared_force_ipv4(key->destination_addr) : tc_local_force_ipv4(key->destination_addr);
    }
    if ((control->flags & SB_TC_FLAG_FORCE_INTERCEPT_IPV6) == 0U) return false;
    return shared ? tc_shared_force_ipv6(key->destination_addr) : tc_local_force_ipv6(key->destination_addr);
}

INLINE bool bypass_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, bool shared) {
    if (flow->family == AF_INET_VALUE) {
        __u32 flag = shared ? SB_TC_FLAG_SHARED_BYPASS_IPV4 : SB_TC_FLAG_LOCAL_BYPASS_IPV4;
        if ((control->flags & flag) == 0U) return false;
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->destination_addr, 4U);
        return shared
            ? map_lookup(&tc_shared_bypass_ipv4, &key) != 0
            : map_lookup(&tc_local_bypass_ipv4, &key) != 0;
    }
    __u32 flag = shared ? SB_TC_FLAG_SHARED_BYPASS_IPV6 : SB_TC_FLAG_LOCAL_BYPASS_IPV6;
    if ((control->flags & flag) == 0U) return false;
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->destination_addr, 16U);
    return shared
        ? map_lookup(&tc_shared_bypass_ipv6, &key) != 0
        : map_lookup(&tc_local_bypass_ipv6, &key) != 0;
}

INLINE bool source_address_excluded(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if (flow->family == AF_INET_VALUE) {
        if ((control->flags & SB_TC_FLAG_EXCLUDE_SOURCE) == 0U) return false;
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->source_addr, 4U);
        return map_lookup(&tc_exclude_source_ipv4, &key) != 0;
    }
    if ((control->flags & SB_TC_FLAG_EXCLUDE_SOURCE) == 0U) return false;
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->source_addr, 16U);
    return map_lookup(&tc_exclude_source_ipv6, &key) != 0;
}

INLINE bool source_address_included(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if ((control->flags & SB_TC_FLAG_INCLUDE_SOURCE) == 0U) return false;
    if (flow->family == AF_INET_VALUE) {
        struct sb_tc_ipv4_lpm_key key = {.prefixlen = 32U};
        __builtin_memcpy(key.address, flow->source_addr, 4U);
        return map_lookup(&tc_include_source_ipv4, &key) != 0;
    }
    struct sb_tc_ipv6_lpm_key key = {.prefixlen = 128U};
    __builtin_memcpy(key.address, flow->source_addr, 16U);
    return map_lookup(&tc_include_source_ipv6, &key) != 0;
}

INLINE bool host_destination(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow) {
    if (flow->family == AF_INET_VALUE) {
        if ((control->flags & SB_TC_FLAG_HOST_IPV4) == 0U) return false;
        struct sb_tc_ipv4_key key = {};
        __builtin_memcpy(key.address, flow->destination_addr, 4U);
        return map_lookup(&tc_host_ipv4, &key) != 0;
    }
    if ((control->flags & SB_TC_FLAG_HOST_IPV6) == 0U) return false;
    struct sb_tc_ipv6_key key = {};
    __builtin_memcpy(key.address, flow->destination_addr, 16U);
    return map_lookup(&tc_host_ipv6, &key) != 0;
}

INLINE bool source_mac_excluded(const struct sb_tc_control *control, const __u8 source_mac[6]) {
    if ((control->flags & SB_TC_FLAG_EXCLUDE_SOURCE_MAC) == 0U) return false;
    struct sb_tc_mac_key key = {};
    __builtin_memcpy(key.address, source_mac, 6U);
    return map_lookup(&tc_exclude_source_mac, &key) != 0;
}

INLINE bool source_mac_included(const struct sb_tc_control *control, const __u8 source_mac[6]) {
    if ((control->flags & SB_TC_FLAG_INCLUDE_SOURCE_MAC) == 0U) return false;
    struct sb_tc_mac_key key = {};
    __builtin_memcpy(key.address, source_mac, 6U);
    return map_lookup(&tc_include_source_mac, &key) != 0;
}

INLINE bool shared_source_selected(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *flow, const __u8 source_mac[6]) {
    if (source_address_excluded(control, flow) || source_mac_excluded(control, source_mac)) return false;
    if ((control->flags & SB_TC_FLAG_SHARED_DEFAULT_BYPASS) == 0U) return true;
    return source_address_included(control, flow) || source_mac_included(control, source_mac);
}

INLINE bool local_selected(struct __sk_buff *skb, const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, __u32 socket_metadata_value) {
    if (force_intercept_destination(control, key, false)) return true;
    __u8 action = port_action(control, key, false);
    if ((action & ~SB_PORT_AFTER_SELECTORS) == SB_PORT_PASS) return false;
    if (action == SB_PORT_INTERCEPT) return true;
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_POLICY_BYPASS) != 0U) return false;
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_POLICY_INTERCEPT) == 0U && uid_bypassed(skb, control)) return false;
    if ((action & ~SB_PORT_AFTER_SELECTORS) == SB_PORT_INTERCEPT) return true;
    if (host_destination(control, key)) return false;
    return !bypass_destination(control, key, false);
}

INLINE bool shared_selected(const struct sb_tc_control *control,
    const struct sb_tc_assign_key *key, const __u8 source_mac[6]) {
    if (force_intercept_destination(control, key, true)) return true;
    __u8 action = port_action(control, key, true);
    if ((action & ~SB_PORT_AFTER_SELECTORS) == SB_PORT_PASS) return false;
    if (action == SB_PORT_INTERCEPT) return true;
    if (!shared_source_selected(control, key, source_mac)) return false;
    if ((action & ~SB_PORT_AFTER_SELECTORS) == SB_PORT_INTERCEPT) return true;
    if (host_destination(control, key)) return false;
    return !bypass_destination(control, key, true);
}

INLINE bool parse_ethernet(void *data, void *data_end, __u16 *protocol, __u32 *l3_offset, __u8 source_mac[6]) {
    struct ethernet_header *ethernet = data;
    if ((void *)(ethernet + 1) > data_end) return false;
    *protocol = network_order16(ethernet->protocol);
    *l3_offset = sizeof(*ethernet);
    __builtin_memcpy(source_mac, ethernet->source, 6U);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 2U; ++depth) {
        if (*protocol != ETH_P_8021Q_VALUE && *protocol != ETH_P_8021AD_VALUE) break;
        struct vlan_header *vlan = data + *l3_offset;
        if ((void *)(vlan + 1) > data_end) return false;
        *protocol = network_order16(vlan->protocol);
        *l3_offset += sizeof(*vlan);
    }
    return true;
}

#define SB_TC_PARSE_PASS 0
#define SB_TC_PARSE_FLOW 1
#define SB_TC_PARSE_FRAGMENT 2

// Fragment parsing is enabled only for replies generated in our private netns.
// External fragments continue to follow the existing pass-through policy.
struct sb_tc_fragment { __u32 id; __u32 state; }; // 0=whole, 1=first, 2=tail

// tcp_flags returns the TCP flag byte. A header that cannot be read is
// reported as a SYN so that callers which act only on connection setup stay
// conservative.
INLINE __u8 tcp_flags(void *transport, void *data_end, __u8 protocol) {
    if (protocol != IPPROTO_TCP_VALUE) return 0U;
    __u8 *flags = transport + TCP_FLAGS_OFFSET;
    if ((void *)(flags + 1) > data_end) return TCP_FLAG_SYN;
    return *flags;
}

// The key fillers report a fragment they do not parse separately, so that
// each caller decides whether and where to count it. flags, when given,
// receives the TCP flag byte of a parsed flow.
INLINE int fill_ipv4_key(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key,
    struct sb_tc_fragment *fragment, __u8 *flags) {
    struct ipv4_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || ip->version != 4U || ip->ihl < 5U ||
        !protocol_enabled(control, ip->protocol)) return SB_TC_PARSE_PASS;
    if ((network_order16(ip->fragment_offset) & (IPV4_FRAGMENT_OFFSET_MASK | IPV4_FRAGMENT_MORE)) != 0U) {
        if (fragment == 0) return SB_TC_PARSE_FRAGMENT;
        fragment->id = network_order16(ip->id);
        fragment->state = (network_order16(ip->fragment_offset) & IPV4_FRAGMENT_OFFSET_MASK) != 0U ? 2U : 1U;
    }
    __u32 header_length = (__u32)ip->ihl * 4U;
    struct transport_ports *ports = (void *)ip + header_length;
    __u16 source_port = 0U, destination_port = 0U;
    if (fragment == 0 || fragment->state != 2U) {
        if ((void *)(ports + 1) > data_end) return SB_TC_PARSE_PASS;
        source_port = network_order16(ports->source);
        destination_port = network_order16(ports->destination);
    }
    if (service_port(ip->protocol, source_port, destination_port)) return SB_TC_PARSE_PASS;
    __u8 destination[4];
    __builtin_memcpy(destination, &ip->destination, 4U);
    if (sb_ebpf_ipv4_safety_bypass(destination)) return SB_TC_PARSE_PASS;
    if (flags != 0) *flags = tcp_flags(ports, data_end, ip->protocol);
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET_VALUE;
    key->protocol = ip->protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    __builtin_memcpy(key->source_addr, &ip->source, 4U);
    __builtin_memcpy(key->destination_addr, &ip->destination, 4U);
    return SB_TC_PARSE_FLOW;
}

INLINE int fill_ipv6_key(void *data, void *data_end, __u32 l3_offset,
    const struct sb_tc_control *control, struct sb_tc_assign_key *key,
    struct sb_tc_fragment *fragment_info, __u8 *flags) {
    struct ipv6_header *ip = data + l3_offset;
    if ((void *)(ip + 1) > data_end || (network_order32(ip->version_flow) >> 28U) != 6U) return SB_TC_PARSE_PASS;
    __u8 protocol = ip->next_header;
    __u32 transport_offset = l3_offset + sizeof(*ip);
#pragma clang loop unroll(full)
    for (__u32 depth = 0U; depth < 4U; ++depth) {
        if (protocol == IPPROTO_FRAGMENT_VALUE) {
            struct ipv6_fragment_header *fragment = data + transport_offset;
            if ((void *)(fragment + 1) > data_end) return SB_TC_PARSE_PASS;
            if ((network_order16(fragment->offset_flags) &
                    (IPV6_FRAGMENT_OFFSET_MASK | IPV6_FRAGMENT_MORE)) != 0U) {
                if (fragment_info == 0 || !protocol_enabled(control, fragment->next_header))
                    return SB_TC_PARSE_FRAGMENT;
                fragment_info->id = network_order32(fragment->identification);
                fragment_info->state = (network_order16(fragment->offset_flags) & IPV6_FRAGMENT_OFFSET_MASK) != 0U ? 2U : 1U;
            }
            protocol = fragment->next_header;
            transport_offset += sizeof(*fragment);
            continue;
        }
        if (protocol != IPPROTO_HOPOPTS_VALUE && protocol != IPPROTO_ROUTING_VALUE &&
            protocol != IPPROTO_DSTOPTS_VALUE && protocol != IPPROTO_AH_VALUE) break;
        struct ipv6_extension_header *extension = data + transport_offset;
        if ((void *)(extension + 1) > data_end) return SB_TC_PARSE_PASS;
        __u32 extension_length = protocol == IPPROTO_AH_VALUE
            ? ((__u32)extension->length + 2U) * 4U
            : ((__u32)extension->length + 1U) * 8U;
        if (extension_length < 8U || data + transport_offset + extension_length > data_end) return SB_TC_PARSE_PASS;
        protocol = extension->next_header;
        transport_offset += extension_length;
    }
    if (!protocol_enabled(control, protocol)) return SB_TC_PARSE_PASS;
    struct transport_ports *ports = data + transport_offset;
    __u16 source_port = 0U, destination_port = 0U;
    if (fragment_info == 0 || fragment_info->state != 2U) {
        if ((void *)(ports + 1) > data_end) return SB_TC_PARSE_PASS;
        source_port = network_order16(ports->source);
        destination_port = network_order16(ports->destination);
    }
    if (service_port(protocol, source_port, destination_port) ||
        sb_ebpf_ipv6_safety_bypass(ip->destination)) return SB_TC_PARSE_PASS;
    if (flags != 0) *flags = tcp_flags(ports, data_end, protocol);
    __builtin_memset(key, 0, sizeof(*key));
    key->family = AF_INET6_VALUE;
    key->protocol = protocol;
    key->source_port = source_port;
    key->destination_port = destination_port;
    copy_address(key->source_addr, ip->source);
    copy_address(key->destination_addr, ip->destination);
    return SB_TC_PARSE_FLOW;
}

// Volatile so that both sides of the pull load the pointers again after it
// and reach the parser in the same verifier state.
#define SKB_DATA(skb) ((void *)(long)*(volatile __u32 *)&(skb)->data)
#define SKB_DATA_END(skb) ((void *)(long)*(volatile __u32 *)&(skb)->data_end)

// Drivers that build received packets in page fragments (napi_gro_frags users
// such as mlx4, sfc and gve, or any device with GRO off) can leave headers GRO
// did not parse, such as a UDP header, outside the linear area that direct
// packet access reads, and the packet would bypass its assignment. The pull
// covers the longest header layout parsed before the transport ports and
// happens before anything is parsed: a packet value kept across the helper
// call loses its bounds on older verifiers, which then walk the rest of the
// program once per side of the pull. A packet whose first bytes are linear,
// including every short linear packet, only pays the compare.
#define SB_TC_PULL_LENGTH_ETHERNET (sizeof(struct ethernet_header) + 2U * sizeof(struct vlan_header) + \
    sizeof(struct ipv6_header) + 8U)
#define SB_TC_PULL_LENGTH_RAW_IP (sizeof(struct ipv6_header) + 8U)

INLINE void pull_headers(struct __sk_buff *skb, __u32 length) {
    __u32 available = skb->len;
    if (available < length) length = available;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (data + length <= data_end) return;
    (void)skb_pull_data(skb, length);
}

// parse_flow fills key for a TCP/UDP flow the data planes may select. A
// fragment is reported separately so that each caller decides whether and
// where to count it. Ingress callers pull headers a driver left in page
// fragments; locally built egress packets always have them linear, and the
// isolated delivery receives packets a selecting program already pulled.
INLINE int parse_flow(struct __sk_buff *skb, const struct sb_tc_control *control,
    __u32 ipv6_flag, bool ethernet, bool pull, struct sb_tc_assign_key *key, __u8 source_mac[6], __u8 *flags) {
    void *data;
    void *data_end;
    if (pull) {
        pull_headers(skb, ethernet ? SB_TC_PULL_LENGTH_ETHERNET : SB_TC_PULL_LENGTH_RAW_IP);
        data = SKB_DATA(skb);
        data_end = SKB_DATA_END(skb);
    } else {
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
    }
    __u16 ether_type;
    __u32 l3_offset;
    if (ethernet) {
        if (!parse_ethernet(data, data_end, &ether_type, &l3_offset, source_mac)) return SB_TC_PARSE_PASS;
    } else {
        ether_type = network_order16(skb->protocol);
        l3_offset = 0U;
        __builtin_memset(source_mac, 0, 6U);
    }
    if (ether_type == ETH_P_IP_VALUE && (control->flags & SB_TC_FLAG_IPV4) != 0U) {
        return fill_ipv4_key(data, data_end, l3_offset, control, key, 0, flags);
    }
    if (ether_type == ETH_P_IPV6_VALUE && (control->flags & ipv6_flag) != 0U) {
        return fill_ipv6_key(data, data_end, l3_offset, control, key, 0, flags);
    }
    return SB_TC_PARSE_PASS;
}

INLINE int parse_pass(int parsed, __u32 fragment_stat) {
    if (parsed == SB_TC_PARSE_FRAGMENT) increment_stat(fragment_stat);
    return TC_ACT_UNSPEC;
}

NOINLINE struct bpf_sock *lookup_tcp_socket(struct __sk_buff *skb,
    const struct sb_tc_control *control, const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    struct bpf_sock *socket = skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
    if (socket != 0 && socket->state != BPF_TCP_LISTEN) return socket;
    if (socket != 0) sk_release(socket);
    __u32 listener = key->family == AF_INET_VALUE ? SB_TC_LISTENER_TCP4 : SB_TC_LISTENER_TCP6;
    struct bpf_sock *registered = map_lookup(&tc_listener_sockets, &listener);
    if (registered != 0) return registered;
    // A SOCKMAP holds only plain TCP sockets, so an MPTCP listener is not
    // registered. Find its TCP subflow listener by port, as the legacy lookup
    // does; this requires a wildcard bind.
    if (key->family == AF_INET_VALUE) {
        tuple.ipv4.dport = network_order16(control->listener_port);
    } else {
        tuple.ipv6.dport = network_order16(control->listener_port);
    }
    return skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
}

NOINLINE struct bpf_sock *lookup_tcp_socket_legacy(struct __sk_buff *skb,
    const struct sb_tc_control *control, const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(key->destination_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    struct bpf_sock *socket = skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
    if (socket != 0 && socket->state != BPF_TCP_LISTEN) return socket;
    if (socket != 0) sk_release(socket);

    // The legacy path has no SOCKMAP. Query the actual transparent listener
    // port after the established-socket lookup so wildcard listeners remain
    // usable on kernels that reject SOCKMAP or map-backed sk_assign.
    if (key->family == AF_INET_VALUE) {
        tuple.ipv4.dport = network_order16(control->listener_port);
    } else {
        tuple.ipv6.dport = network_order16(control->listener_port);
    }
    return skc_lookup_tcp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
}

NOINLINE struct bpf_sock *lookup_udp_socket(struct __sk_buff *skb,
    const struct sb_tc_control *control, const struct sb_tc_assign_key *key) {
    struct bpf_sock_tuple tuple = {};
    __u32 tuple_size;
    if (key->family == AF_INET_VALUE) {
        __builtin_memcpy(&tuple.ipv4.saddr, key->source_addr, 4U);
        __builtin_memcpy(&tuple.ipv4.daddr, key->destination_addr, 4U);
        tuple.ipv4.sport = network_order16(key->source_port);
        tuple.ipv4.dport = network_order16(control->listener_port);
        tuple_size = sizeof(tuple.ipv4);
    } else {
        copy_address((__u8 *)&tuple.ipv6.saddr, key->source_addr);
        copy_address((__u8 *)&tuple.ipv6.daddr, key->destination_addr);
        tuple.ipv6.sport = network_order16(key->source_port);
        tuple.ipv6.dport = network_order16(control->listener_port);
        tuple_size = sizeof(tuple.ipv6);
    }
    return sk_lookup_udp(skb, &tuple, tuple_size, BPF_F_CURRENT_NETNS, 0U);
}

INLINE bool source_mac_equal(const __u8 left[6], const __u8 right[6]) {
    __u32 left_low, right_low;
    __u16 left_high, right_high;
    __builtin_memcpy(&left_low, left, 4U);
    __builtin_memcpy(&right_low, right, 4U);
    __builtin_memcpy(&left_high, left + 4U, 2U);
    __builtin_memcpy(&right_high, right + 4U, 2U);
    return left_low == right_low && left_high == right_high;
}

#include "tc_isolation.h"

INLINE int local_egress_mark(struct __sk_buff *skb, bool ethernet, bool track_process) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U || control->delivery_ifindex == 0U) return TC_ACT_UNSPEC;
    if (skb->ingress_ifindex != 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    __u8 flags = 0U;
    // Parse before the socket-metadata lookup: packets this path can never
    // select (disabled families, other protocols, service or safety
    // addresses) then skip it. Fragments are still counted only after the
    // self-bypass check.
    int parsed = parse_flow(skb, control, SB_TC_FLAG_LOCAL_IPV6, ethernet, false, &key, source_mac, &flags);
    if (parsed == SB_TC_PARSE_PASS) return TC_ACT_UNSPEC;
    __u64 socket_cookie = get_socket_cookie(skb);
    __u32 socket_metadata_value = socket_metadata(socket_cookie);
    if ((socket_metadata_value & SB_EBPF_SOCKET_METADATA_SELF_BYPASS) != 0U) return TC_ACT_UNSPEC;
    if (parsed != SB_TC_PARSE_FLOW) return parse_pass(parsed, SB_TC_STAT_LOCAL_FRAGMENT_PASS);
    if (!local_selected(skb, control, &key, socket_metadata_value)) return TC_ACT_UNSPEC;
    return redirect_isolated(skb, control, &key, track_process ? socket_cookie : 0U,
        SB_TC_PATH_DELIVERY | (ethernet ? SB_TC_RETURN_ETHERNET : 0U) | assignment_record(&key, flags));
}

SEC("classifier/local_egress_ethernet_isolated")
int sing_ebpf_tc_local_ethernet_isolated(struct __sk_buff *skb) { return local_egress_mark(skb, true, false); }
SEC("classifier/local_egress_raw_ip_isolated")
int sing_ebpf_tc_local_raw_isolated(struct __sk_buff *skb) { return local_egress_mark(skb, false, false); }
SEC("classifier/local_egress_ethernet_isolated_process")
int sing_ebpf_tc_local_ethernet_isolated_process(struct __sk_buff *skb) { return local_egress_mark(skb, true, true); }
SEC("classifier/local_egress_raw_ip_isolated_process")
int sing_ebpf_tc_local_raw_isolated_process(struct __sk_buff *skb) { return local_egress_mark(skb, false, true); }

INLINE int shared_isolated(struct __sk_buff *skb, bool ethernet) {
    const struct sb_tc_control *control = load_control();
    if (control == 0 || control->enabled == 0U || control->delivery_ifindex == 0U) return TC_ACT_UNSPEC;
    struct sb_tc_assign_key key;
    __u8 source_mac[6];
    __u8 flags = 0U;
    int parsed = parse_flow(skb, control, SB_TC_FLAG_SHARED_IPV6, ethernet, true, &key, source_mac, &flags);
    if (parsed != SB_TC_PARSE_FLOW) return parse_pass(parsed, SB_TC_STAT_SHARED_FRAGMENT_PASS);
    if (!ethernet && (control->flags & (SB_TC_FLAG_INCLUDE_SOURCE_MAC | SB_TC_FLAG_EXCLUDE_SOURCE_MAC)) != 0U)
        return TC_ACT_UNSPEC;
    if (!shared_selected(control, &key, source_mac)) return TC_ACT_UNSPEC;
    return redirect_isolated(skb, control, &key, 0U,
        SB_TC_PATH_SHARED | (ethernet ? SB_TC_RETURN_ETHERNET : 0U) | assignment_record(&key, flags));
}
SEC("classifier/shared_ingress_ethernet_isolated")
int sing_ebpf_tc_shared_ethernet_isolated(struct __sk_buff *skb) { return shared_isolated(skb, true); }
SEC("classifier/shared_ingress_raw_ip_isolated")
int sing_ebpf_tc_shared_raw_isolated(struct __sk_buff *skb) { return shared_isolated(skb, false); }

char _license[] SEC("license") = "GPL";
