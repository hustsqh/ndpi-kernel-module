#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/notifier.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>

#include <net/netfilter/nf_conntrack.h>

#include <linux/netfilter/ndpi/ndpi_main.h>
#include <linux/netfilter/ndpi/nf_ndpi_main.h>

#include <uapi/linux/netfilter/xt_ndpi.h>


#define NDPI_BITMASK_IS_ZERO(a) NDPI_BITMASK_IS_EMPTY(a)


static int ndpi_mt_check(const struct xt_mtchk_param *par)
{
    const struct xt_ndpi_mtinfo *info = par->matchinfo;
    int ret = 0;

    if(NDPI_BITMASK_IS_ZERO(info->flags)){
        pr_info("none selected protocol.\n");
        return -EINVAL;
    }

    // enable conntrack
    ret = nf_ct_netns_get (par->net, par->family);
    if (ret)
        pr_info_ratelimited("cannot load conntrack support for proto=%u\n",
				    par->family);
    return ret;
}

static bool ndpi_match(const struct sk_buff *skb, struct xt_action_param *par)
{
    struct nf_conn *ct;
    struct nf_conn_ndpi *proto;
    const struct xt_ndpi_mtinfo *info = par->matchinfo;
    enum ip_conntrack_info ctinfo;

    ct = nf_ct_get(skb, &ctinfo);
    if(ct == NULL){
        return false;
    }

    proto = nf_get_ndpi_protocol(ct);
    if(proto == NULL){
        return false;
    }

    if(proto->checked){
        return (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, proto->protocol_id) != 0);
    }

    return false;
}

static void ndpi_mt_destroy(const struct xt_mtdtor_param *par)
{
    //const struct xt_ndpi_mtinfo *info = par->matchinfo;

    nf_ct_netns_put(par->net, par->family);
}

static struct xt_match ndpi_mt_reg __read_mostly = {
    .name = "ndpi",
    .revision = 0,
    .family = NFPROTO_IPV4,
    .match = ndpi_match,
    .checkentry = ndpi_mt_check,
    .destroy = ndpi_mt_destroy,
    .matchsize = sizeof(struct xt_ndpi_mtinfo),
    .me = THIS_MODULE,
};

static int __init ndpi_mt_init(void)
{
    int ret;

    ret = xt_register_match(&ndpi_mt_reg);
    if(ret != 0){
        pr_err("xt_register_match failed %d,", ret);
        return ret;
    }
    pr_info("xt_register_match succ!");
    return 0;
}

static void __exit ndpi_mt_fini(void)
{
    xt_unregister_match(&ndpi_mt_reg);
    pr_info("ndpi_mt_fini succ!");
}

module_init(ndpi_mt_init);
module_exit(ndpi_mt_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("xxxx");
MODULE_AUTHOR("aa@gmail.com");
MODULE_DESCRIPTION("ndpi xt match");
MODULE_ALIAS("ipt_ndpi");
