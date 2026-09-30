//go:build with_ebpf && (linux || android)

// Package singebpf provides experimental Linux and Android eBPF data-plane
// mechanisms for transparent TCP and UDP redirection.
//
// The package owns BPF sources and generated objects, their Go/C ABI, maps,
// programs, capability selection, final-action policy compilation, redirect
// state, cgroup and TC backends, self-bypass, and process tracking. The
// supported data-plane roles are local cgroup, local TC socket assignment,
// shared TC socket assignment, and shared packet rewrite.
//
// The sibling runtime package owns interface attachment and reconciliation,
// TC/TCX links, delivery links, policy routes, modified sysctls, and rollback.
// It borrows backend handles through an internal bridge rather than exposing
// raw kernel resources to consumers.
//
// Policy crossing this package boundary uses final actions only:
//
//   - DecisionPass leaves the operation untouched.
//   - DecisionIntercept redirects or assigns it to the eBPF listener.
//
// The package does not interpret consumer configuration or application
// semantics such as DNS modes, FakeIP, rule sets, package names, outbound
// selection, or UDP session handling. Those responsibilities belong to the
// consumer.
//
// Raw BPF maps, programs, and file descriptors remain internal implementation
// details. Consumers receive lifecycle owners and value-level operations, and
// must retain and close those owners according to their documented lifetime.
package singebpf
