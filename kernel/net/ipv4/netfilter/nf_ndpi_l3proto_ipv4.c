#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/ip.h>

#include <linux/netfilter/ndpi/nf_ndpi_main.h>

static DEFINE_MUTEX(ndpi_ipv4_mutex);


static unsigned int ipv4_nf_ndpi_in(void *priv,
				      struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
    pr_err("ipv4_nf_ndpi_in in %d", state->hook);
    nf_ndpi_in(state->net, state->pf, state->hook, skb);
    return NF_ACCEPT;
}

                     
static const struct nf_hook_ops ipv4_nf_ndpi_ops[] = {
    {
        .hook = ipv4_nf_ndpi_in,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_NDPI,
    },
    {
        .hook = ipv4_nf_ndpi_in,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_NDPI,
    },
};


static int nf_ndpi_ipv4_enable(struct net *net)
{
    int err = 0;

    might_sleep();

    if(net->nf.ndpi_ipv4)
        return 0;

    mutex_lock(&ndpi_ipv4_mutex);
    if(net->nf.ndpi_ipv4)
        goto out_unlock;

    err = nf_register_net_hooks(net, ipv4_nf_ndpi_ops, ARRAY_SIZE(ipv4_nf_ndpi_ops));
    if(err == 0){
        net->nf.ndpi_ipv4 = true;
    }

out_unlock:
    mutex_unlock(&ndpi_ipv4_mutex);
    return err;
}

static void __net_exit nf_ndpi_ipv4_net_exit(struct net *net)
{
    if(net->nf.ndpi_ipv4){
        mutex_lock(&ndpi_ipv4_mutex);
        nf_unregister_net_hooks(net, ipv4_nf_ndpi_ops,
					ARRAY_SIZE(ipv4_nf_ndpi_ops));
        net->nf.ndpi_ipv4 = false;
        mutex_unlock(&ndpi_ipv4_mutex);
    }
}


static struct pernet_operations nf_ndpi_ipv4_net_ops = {
    .exit = nf_ndpi_ipv4_net_exit,
};


static int __init nf_ndpi_ipv4_init(void)
{
    int err = register_pernet_subsys(&nf_ndpi_ipv4_net_ops);
    if (err)
		return err;

    err = nf_ndpi_ipv4_enable(&init_net);
    if(err){
        unregister_pernet_subsys(&nf_ndpi_ipv4_net_ops);
    }

    return err;
}

static void __exit nf_ndpi_ipv4_fini(void)
{
    unregister_pernet_subsys(&nf_ndpi_ipv4_net_ops);
}



module_init(nf_ndpi_ipv4_init);
module_exit(nf_ndpi_ipv4_fini);

MODULE_LICENSE("GPL");

