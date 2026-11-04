// The socket-storage cgroup variant shares the policy and redirect program
// implementation with cgroup.bpf.c, but binds peer restoration state to the
// kernel socket lifetime instead of a cookie-keyed LRU map.
#define SB_EBPF_USE_SK_STORAGE
#include "cgroup.bpf.c"
