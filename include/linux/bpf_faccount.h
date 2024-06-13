/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_FACCOUNT_H
#define _BPF_FACCOUNT_H

#include <linux/bpf.h>
// #include <linux/faccount_hooks.h>

#ifdef CONFIG_BPF_FACCOUNT

#define BPF_FACCOUNT_HOOK(RET, DEFAULT, NAME, ...)                                \
	RET bpf_faccount_##NAME(__VA_ARGS__);
#include <linux/faccount_hook_defs.h>
#undef BPF_FACCOUNT_HOOK

int bpf_faccount_verify_prog(struct bpf_verifier_log *vlog,
			  const struct bpf_prog *prog);

// DECLARE_STATIC_KEY_FALSE(bpf_sched_enabled_key);

// static inline bool bpf_sched_enabled(void)
// {
// 	return static_branch_unlikely(&bpf_sched_enabled_key);
// }

// static inline void bpf_sched_inc(void)
// {
// 	static_branch_inc(&bpf_sched_enabled_key);
// }

// static inline void bpf_sched_dec(void)
// {
// 	static_branch_dec(&bpf_sched_enabled_key);
// }

#else /* !CONFIG_BPF_FACCOUNT */

#define BPF_FACCOUNT_HOOK(RET, DEFAULT, NAME, ...)                                \
	static inline RET bpf_faccount_##NAME(__VA_ARGS__)                        \
	{                                                                      \
		return DEFAULT;                                                \
	}
#include <linux/faccount_hook_defs.h>
#undef BPF_FACCOUNT_HOOK

#endif /* CONFIG_BPF_FACCOUNT */

#endif /* _BPF_FACCOUNT_H */

