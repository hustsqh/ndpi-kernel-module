/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_NETFILTER_H
#define __NETNS_NETFILTER_H

#include <linux/netfilter_defs.h>

struct proc_dir_entry;
struct nf_logger;
struct nf_queue_handler;

struct netns_nf {
#if defined CONFIG_PROC_FS
	struct proc_dir_entry *proc_netfilter;
#endif
	const struct nf_queue_handler __rcu *queue_handler;
	const struct nf_logger __rcu *nf_loggers[NFPROTO_NUMPROTO];
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *nf_log_dir_header;
#endif
	struct nf_hook_entries __rcu *hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS];
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV4)
	bool			defrag_ipv4;
#endif
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV6)
	bool			defrag_ipv6;
#endif
#if IS_ENABLED(CONFIG_NF_NDPI_IPV4)
    bool            ndpi_ipv4;
#endif
#if IS_ENABLED(CONFIG_NF_NDPI_IPV6)
    bool            ndpi_ipv6;
#endif

};
#endif
