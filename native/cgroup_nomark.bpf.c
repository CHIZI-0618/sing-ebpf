// The legacy cgroup variant omits bpf_sock->mark access. Linux 4.19 accepts
// the remaining cgroup hooks but rejects that field in the verifier.
#define SB_EBPF_DISABLE_SOCKET_MARK
#include "cgroup.bpf.c"
