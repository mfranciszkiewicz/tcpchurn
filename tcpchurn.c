#define KBUILD_MODNAME "tcpchurn"

#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

enum {
    ACCEPT = 0,
    CONNECT,
    CLOSE
};

typedef struct u128 {
    u64 h;
    u64 l;
} u128;

struct ipv4_data_t {
    u64 ts_us;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 pid;
    u64 state;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64  ts_us;
    u128 saddr;
    u128 daddr;
    u16  sport;
    u16  dport;
    u32  pid;
    u64  state;
};
BPF_PERF_OUTPUT(ipv6_events);


BPF_HASH(conns, u32, struct sock *);


static inline void submit_event(struct pt_regs* ctx_p, struct sock* sk_p,
                                u64 ts, u32 pid, u8 state) {

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family),
        &sk_p->__sk_common.skc_family);

    if (family == AF_INET) {

        struct ipv4_data_t ipv4_data = {
            .ts_us = ts,
            .pid = pid,
            .state = state
        };

        bpf_probe_read(&ipv4_data.sport, sizeof(ipv4_data.sport),
            &sk_p->__sk_common.skc_num);
        bpf_probe_read(&ipv4_data.dport, sizeof(ipv4_data.dport),
            &sk_p->__sk_common.skc_dport);
        bpf_probe_read(&ipv4_data.saddr, sizeof(ipv4_data.saddr),
            &sk_p->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&ipv4_data.daddr, sizeof(ipv4_data.daddr),
            &sk_p->__sk_common.skc_daddr);

        ipv4_events.perf_submit(ctx_p, &ipv4_data, sizeof(ipv4_data));

    } else if (family == AF_INET6) {

        struct ipv6_data_t ipv6_data = {
            .ts_us = ts,
            .pid = pid,
            .state = state
        };

        bpf_probe_read(&ipv6_data.sport, sizeof(ipv6_data.sport),
            &sk_p->__sk_common.skc_num);
        bpf_probe_read(&ipv6_data.dport, sizeof(ipv6_data.dport),
            &sk_p->__sk_common.skc_dport);
        bpf_probe_read(&ipv6_data.saddr, sizeof(ipv6_data.saddr),
            &sk_p->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&ipv6_data.daddr, sizeof(ipv6_data.daddr),
            &sk_p->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        ipv6_events.perf_submit(ctx_p, &ipv6_data, sizeof(ipv6_data));
    }
}

static inline int pid_matches(u32 pid) {
    return pid == PID;
}


int kretprobe__inet_csk_accept(struct pt_regs *ctx_p) {
    struct sock *sk_p = (struct sock *) PT_REGS_RC(ctx_p);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 protocol = 0;

    // FIXME: workaround for reading the sk_protocol bitfield
	bpf_probe_read(&protocol, 1, (void *)((long) &sk_p->sk_wmem_queued) - 3);
    if (protocol != IPPROTO_TCP)
        return 0;

    if (pid_matches(pid)) {
        u64 ts = bpf_ktime_get_ns() / 1000;
        submit_event(ctx_p, sk_p, ts, pid, ACCEPT);
    }

    return 0;
}


int kprobe__tcp_connect(struct pt_regs *ctx_p, struct sock *sk_p) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    conns.update(&pid, &sk_p);

    return 0;
}

int kretprobe__tcp_connect(struct pt_regs *ctx_p) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock **sk_pp = conns.lookup(&pid);

    if (sk_pp != 0 && pid_matches(pid)) {
        u64 ts = bpf_ktime_get_ns() / 1000;
        submit_event(ctx_p, *sk_pp, ts, pid, CONNECT);
        conns.delete(&pid);
    }

    return 0;
}


int kprobe__tcp_close(struct pt_regs *ctx_p, struct sock *sk_p) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (pid_matches(pid)) {
        u64 ts = bpf_ktime_get_ns() / 1000;
        submit_event(ctx_p, sk_p, ts, pid, CLOSE);
    }

    return 0;
}
