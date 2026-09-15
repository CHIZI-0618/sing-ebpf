// Copyright 2026, sing-box contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SING_EBPF_FORCE_INTERCEPT_POLICY_H
#define SING_EBPF_FORCE_INTERCEPT_POLICY_H

#include "private_address.h"

// ForceIntercept destinations are mandatory interception targets. The caller supplies
// the data-plane-specific flag and normalized prefix from its control object.
static __attribute__((always_inline)) bool sb_ebpf_force_intercept_ipv4(
    const __u8 destination[4],
    __u32 flags,
    __u32 enabled_flag,
    const __u8 prefix[4],
    const __u8 mask[4]) {
    return (flags & enabled_flag) != 0U &&
        sb_ebpf_ipv4_prefix_match(destination, prefix, mask);
}

static __attribute__((always_inline)) bool sb_ebpf_force_intercept_ipv6(
    const __u8 destination[16],
    __u32 flags,
    __u32 enabled_flag,
    const __u8 prefix[16],
    const __u8 mask[16]) {
    return (flags & enabled_flag) != 0U &&
        sb_ebpf_prefix_match(destination, prefix, mask);
}

#endif
