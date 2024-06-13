// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/cgroup.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf_faccount.h>
#include <linux/btf_ids.h>

/*
 * For every hook declare a nop function where a BPF program can be attached.
 */
#define BPF_FACCOUNT_HOOK(RET, DEFAULT, NAME, ...)                             \
	noinline RET bpf_faccount_##NAME(__VA_ARGS__)                          \
	{                                                                      \
		return DEFAULT;                                                \
	}
#include <linux/faccount_hook_defs.h>
#undef BPF_FACCOUNT_HOOK

#define BPF_FACCOUNT_HOOK(RET, DEFAULT, NAME, ...)                             \
	BTF_ID(func, bpf_faccount_##NAME)
BTF_SET_START(bpf_faccount_hooks)
#include <linux/faccount_hook_defs.h>
#undef BPF_FACCOUNT_HOOK
BTF_SET_END(bpf_faccount_hooks)

int bpf_faccount_verify_prog(struct bpf_verifier_log *vlog,
			     const struct bpf_prog *prog)
{
	if (!prog->gpl_compatible) {
		bpf_log(vlog,
			"faccount programs must have a GPL compatible license\n");
		return -EINVAL;
	}

	if (!btf_id_set_contains(&bpf_faccount_hooks,
				 prog->aux->attach_btf_id)) {
		bpf_log(vlog, "attach_btf_id %u points to wrong type name %s\n",
			prog->aux->attach_btf_id, prog->aux->attach_func_name);
		return -EINVAL;
	}

	return 0;
}

// ==== 待改start ====
BPF_CALL_2(faccount_func, void *, a1, void *, a2)
{
	return 0;
}

BTF_ID_LIST_SINGLE(faccount_func_btf_ids, void, *)

static const struct bpf_func_proto faccount_func_proto = {
	.func = faccount_func,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_BTF_ID,
	.arg1_btf_id = &faccount_func_btf_ids[0],
	.arg2_type = ARG_ANYTHING,
};

static const struct bpf_func_proto *
bpf_faccount_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_faccount_func:
		return &faccount_func_proto;
	default:
		return tracing_prog_func_proto(func_id, prog);
	}
}

const struct bpf_prog_ops bpf_account_prog_ops = {};

const struct bpf_verifier_ops bpf_account_verifier_ops = {
	.get_func_proto = bpf_faccount_func_proto,
	.is_valid_access = btf_ctx_access,
};
// ==== 待改end ====