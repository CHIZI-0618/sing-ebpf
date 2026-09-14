//go:build with_ebpf && (linux || android)

// Package singebpf implements reusable Linux kernel-facing mechanisms for
// transparent traffic redirection with cgroup and TC eBPF programs.
//
// The package owns BPF source and generated objects, their Go/C ABI, map and
// program loading, capability selection, kernel policy state, redirect token
// routes, and the cgroup attachments whose lifetime is inseparable from those
// objects. It deliberately does not interpret consumer configuration, routing
// rules, outbound selection, process metadata, or connection/session semantics.
// Those application-facing responsibilities belong to the consumer.
//
// Exported BPF map, program, and FD accessors return borrowed values for the
// sibling runtime package. They do not transfer ownership and callers must not
// close or retain them beyond the owning backend's lifetime.
package singebpf
