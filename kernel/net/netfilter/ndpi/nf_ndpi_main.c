
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/notifier.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/time.h>
#include <net/tcp.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>

#include <linux/netfilter/ndpi/ndpi_main.h>
#include <linux/netfilter/ndpi/nf_ndpi_main.h>

//#define NDPI_BITMASK_IS_ZERO(a) NDPI_BITMASK_IS_EMPTY(a)
#define NDPI_LAST_NFPROTO NDPI_LAST_IMPLEMENTED_PROTOCOL

static const u32 detection_tick_resolution = 1000;


static DEFINE_SPINLOCK(flow_lock);
static DEFINE_SPINLOCK(ipq_lock);

struct nf_ndpi_flow_node{
    struct rb_node node;
    struct nf_conn *ct;
    u_int64_t ndpi_timeout;
    u8 detection_completed;
    ndpi_protocol detected_proto;
    struct ndpi_flow_struct *ndpi_flow;
};

struct nf_ndpi_id_node{
    struct rb_node node;
    struct kref refcnt;
    union nf_inet_addr ip;
    struct ndpi_id_struct *ndpi_id;
};

static int debug_dpi = 0;


static struct rb_root s_nf_ndpi_flow_root = RB_ROOT;
static struct rb_root s_nf_ndpi_id_root = RB_ROOT;

static struct kmem_cache *s_nf_ndpi_flow_cache __read_mostly;
static struct kmem_cache *s_nf_ndpi_id_cache __read_mostly;

static struct ndpi_detection_module_struct *ndpi_struct = NULL;

static u64 gc_interval_timeout = 0;

static char *prot_long_str[] = { NDPI_PROTOCOL_LONG_STRING };


static int nf_ndpi_flow_insert(struct rb_root *root, struct nf_ndpi_flow_node *data)
{
    struct nf_ndpi_flow_node *this;
    struct rb_node ** new = &(root->rb_node), *parent = NULL;

    while(*new){
        this = rb_entry(*new, struct nf_ndpi_flow_node, node);
        parent = *new;
        if (data->ct < this->ct){
            new = &((*new)->rb_left);
        }else if(data->ct > this->ct){
            new = &((*new)->rb_right);
        }else{
            return 0;
        }
    }
    rb_link_node(&data->node, parent, new);
    rb_insert_color(&data->node, root);
    return 1;
}



static struct nf_ndpi_flow_node *nf_ndpi_alloc_flow(struct nf_conn *ct)
{
    struct nf_ndpi_flow_node *flow;
    flow = kmem_cache_zalloc(s_nf_ndpi_flow_cache, GFP_ATOMIC);
    if (flow == NULL){
        pr_err("malloc flow failed!");
        return NULL;
    }else{
        flow->ct = ct;
        flow->ndpi_flow = (struct ndpi_flow_struct *)((char *)&flow->ndpi_flow + sizeof(flow->ndpi_flow));
        nf_ndpi_flow_insert(&s_nf_ndpi_flow_root, flow);
    }
    return flow;
}

static struct nf_ndpi_flow_node *nf_ndpi_flow_search(struct rb_root *root, struct nf_conn *ct)
{
    struct nf_ndpi_flow_node *data;
    struct rb_node *node = root->rb_node;

    while(node){
        data = rb_entry(node, struct nf_ndpi_flow_node, node);
        if(ct < data->ct){
            node = node->rb_left;
        }else if(ct > data->ct){
            node = node->rb_right;
        }else {
            return data;
        }
    }
    return NULL;
}


static void nf_ndpi_free_flow(struct nf_conn * ct, struct nf_ndpi_flow_node *old)
{
    struct nf_ndpi_flow_node *flow;

    if(old == NULL){
        flow = nf_ndpi_flow_search(&s_nf_ndpi_flow_root, ct);
    }else {
        flow = old;
        if(flow != NULL){
            rb_erase(&flow->node, &s_nf_ndpi_flow_root);
            kmem_cache_free(s_nf_ndpi_flow_cache, flow);
        }
    }
}


static struct nf_ndpi_id_node * nf_ndpi_id_search(struct rb_root *root, union nf_inet_addr *ip)
{
    int res;
    struct nf_ndpi_id_node *data;
  	struct rb_node *node = root->rb_node;

    while (node) {
        data = rb_entry(node, struct nf_ndpi_id_node, node);
		res = memcmp(ip, &data->ip, sizeof(union nf_inet_addr));

		if (res < 0)
  			node = node->rb_left;
		else if (res > 0)
  			node = node->rb_right;
		else
  			return data;
	}
    return NULL;
}

static int nf_ndpi_id_insert(struct rb_root *root, struct nf_ndpi_id_node *data)
{
    int res;
    struct nf_ndpi_id_node *this;
  	struct rb_node **new = &(root->rb_node), *parent = NULL;

  	while (*new) {
        this = rb_entry(*new, struct nf_ndpi_id_node, node);
		res = memcmp(&data->ip, &this->ip, sizeof(union nf_inet_addr));

		parent = *new;
  		if (res < 0)
  			new = &((*new)->rb_left);
  		else if (res > 0)
  			new = &((*new)->rb_right);
  		else
  			return 0;
  	}

  	rb_link_node(&data->node, parent, new);
  	rb_insert_color(&data->node, root);

	return 1;
}



static struct nf_ndpi_id_node *nf_ndpi_alloc_id(union nf_inet_addr *ip)
{
    struct nf_ndpi_id_node *id;

    id = kmem_cache_zalloc(s_nf_ndpi_id_cache, GFP_ATOMIC);
    if(!id){
        pr_err("malloc nf_ndpi_id_node failed!");
        return NULL;
    }

    memcpy(&id->ip, ip, sizeof(union nf_inet_addr));
    id->ndpi_id = (struct ndpi_id_struct *)((char *)&id->ndpi_id + sizeof(id->ndpi_id));
    kref_init(&id->refcnt);
    nf_ndpi_id_insert(&s_nf_ndpi_id_root, id);
    
    return id;
}

static void nf_ndpi_id_release(struct kref *kref)
{
    struct nf_ndpi_id_node *id;
    id = container_of(kref, struct nf_ndpi_id_node, refcnt);
    rb_erase(&id->node, &s_nf_ndpi_id_root);
    kmem_cache_free(s_nf_ndpi_id_cache, id);
}


static void nf_ndpi_free_id(union nf_inet_addr * ip)
{
    struct nf_ndpi_id_node *id;

    id = nf_ndpi_id_search(&s_nf_ndpi_id_root, ip);
    if(id){
        kref_put(&id->refcnt, nf_ndpi_id_release);
    }
}

static void nf_ndpi_kill_flow(struct nf_conn * ct, union nf_inet_addr *ipsrc, 
                                    union nf_inet_addr *ipdst)
{
    nf_ndpi_free_id(ipsrc);
    nf_ndpi_free_id(ipdst);
    nf_ndpi_free_flow(ct, NULL);
}


static void nf_ndpi_gc_flow(void)
{
    struct nf_conn *ct;
    struct rb_node * next;
    struct nf_ndpi_flow_node *flow;
	union nf_inet_addr *ipdst;

    u64 t1;
    struct timeval tv;

    do_gettimeofday(&tv);
    t1 = (uint64_t) tv.tv_sec;

    next = rb_first(&s_nf_ndpi_flow_root);
    while(next){
        flow = rb_entry(next, struct nf_ndpi_flow_node, node);
        next = rb_next(&flow->node);
        if(flow && (flow->ndpi_timeout > 180)){
            ct = flow->ct;
            ipdst = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;
            if (debug_dpi && flow->detected_proto.app_protocol < NDPI_LAST_NFPROTO){
                pr_info ("xt_ndpi: deleted by garbage collector - proto %s - dst %pI4\n", prot_long_str[flow->detected_proto.app_protocol], ipdst);
            }
            nf_ndpi_free_id(&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3);
            nf_ndpi_free_id(ipdst);
            nf_ndpi_free_flow(ct, flow);
        }
    }
}

static void update_protocol_to_ct(struct nf_conn *ct, u32 protocol)
{
    if(protocol > NDPI_PROTOCOL_UNKNOWN && protocol < NDPI_LAST_NFPROTO){
        struct nf_conn_ndpi *proto = nf_get_ndpi_protocol(ct);
        if(proto){
            proto->checked = true;
            proto->protocol_id = protocol;
        }else{
            pr_err("nf_get_ndpi_protocol failed!");
        }
    }
}

static u32 ndpi_process_packet(struct nf_conn *ct, const uint64_t time, const struct iphdr *iph,
                                    uint16_t ipsize, const struct tcphdr *tcph)
{
    u32 proto = NDPI_PROTOCOL_UNKNOWN;
    union nf_inet_addr *ipsrc, *ipdst;
    struct nf_ndpi_id_node *src, *dst;
    struct nf_ndpi_flow_node *flow, *curflow;

    u8 exist_flow=0;
    u64 t1;
    struct timeval tv;

    if(ndpi_struct == NULL){
        return proto;
    }

    spin_lock_bh(&flow_lock);
    ipsrc = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
    ipdst = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;

    flow = nf_ndpi_flow_search(&s_nf_ndpi_flow_root, ct);

    if(iph->protocol == IPPROTO_TCP){
        if(tcph->syn){
            spin_unlock_bh (&flow_lock);
			return proto;
        }else if((tcph->fin || tcph->rst) && flow != NULL){
            nf_ndpi_kill_flow(ct, ipsrc, ipdst);
            spin_unlock_bh (&flow_lock);
            return proto;
        }
    }else if(iph->protocol == IPPROTO_ICMP){
        spin_unlock_bh (&flow_lock);
		return NDPI_PROTOCOL_IP_ICMP;
    }else {
        if(nf_ct_is_dying(ct)){
            nf_ndpi_kill_flow(ct, ipsrc, ipdst);
			spin_unlock_bh (&flow_lock);
			return proto;
        }
    }
    
    do_gettimeofday(&tv);
    t1 = (uint64_t) tv.tv_sec;

    if(flow == NULL){
        if(!gc_interval_timeout){
            gc_interval_timeout = t1;
        }else{
            if(t1 - gc_interval_timeout > 59){
                nf_ndpi_gc_flow();
                gc_interval_timeout = t1;
            }
        }
        flow = nf_ndpi_alloc_flow(ct);
        if(!flow){
            spin_unlock_bh (&flow_lock);
            return NDPI_PROTOCOL_UNKNOWN;
        }
        flow->ndpi_timeout = t1;
        flow->detected_proto.app_protocol = NDPI_PROTOCOL_UNKNOWN;
        flow->detection_completed = 0;
    }else {
        exist_flow = 1;
        if (flow->detected_proto.app_protocol){
            proto = flow->detected_proto.app_protocol;
            if (debug_dpi && flow->detected_proto.app_protocol < NDPI_LAST_NFPROTO)
				pr_info ("xt_ndpi: flow detected %s ( dst %pI4 )\n", prot_long_str[flow->detected_proto.app_protocol], ipdst);

            flow->ndpi_timeout = t1;
            spin_unlock_bh (&flow_lock);
			return proto;
        }else if (!flow->detected_proto.app_protocol && (t1 - flow->ndpi_timeout > 30)){
            if (debug_dpi) pr_info ("xt_ndpi: dst %pI4 expired\n", ipdst);
            spin_unlock_bh (&flow_lock);
			return NDPI_PROTOCOL_UNKNOWN;
        }
    }

    if (flow->ndpi_flow == NULL) {
        if (debug_dpi) pr_info ("xt_ndpi: dst %pI4 invalid\n", ipdst);
		nf_ndpi_kill_flow(ct, ipsrc, ipdst);
		spin_unlock_bh (&flow_lock);
        return proto;
    }

    flow->ndpi_timeout = t1;

	/* Set current flow for temporary dump */
    curflow = kmem_cache_zalloc (s_nf_ndpi_flow_cache, GFP_ATOMIC);
    curflow->ndpi_flow = (struct ndpi_flow_struct *)((char*)&curflow->ndpi_flow + sizeof(curflow->ndpi_flow));
    curflow->detected_proto.app_protocol = NDPI_PROTOCOL_UNKNOWN;
    curflow->ndpi_flow = flow->ndpi_flow;

    src = nf_ndpi_id_search (&s_nf_ndpi_id_root, ipsrc);
	if (src == NULL) {
        src = nf_ndpi_alloc_id(ipsrc);
        if (src == NULL) {
			kmem_cache_free (s_nf_ndpi_flow_cache, curflow);
		    spin_unlock_bh (&flow_lock);
			return proto;
		}
	} else if (!exist_flow) {
        kref_get (&src->refcnt);
	}

    dst = nf_ndpi_id_search (&s_nf_ndpi_id_root, ipdst);
	if (dst == NULL) {
        dst = nf_ndpi_alloc_id(ipdst);
        if (dst == NULL) {
			kmem_cache_free (s_nf_ndpi_flow_cache, curflow);
		    spin_unlock_bh (&flow_lock);
			return proto;
		}
	} else if (!exist_flow) {
	    kref_get (&dst->refcnt);
	}
	spin_unlock_bh (&flow_lock);

    /* here the actual detection is performed */
	spin_lock_bh (&ipq_lock);
	curflow->detected_proto = ndpi_detection_process_packet(ndpi_struct,curflow->ndpi_flow,
                                          (uint8_t *) iph, ipsize, time,
                                          src->ndpi_id, dst->ndpi_id);

	spin_unlock_bh (&ipq_lock);

	/* set detected protocol */
	spin_lock_bh (&flow_lock);
	if (flow != NULL) {
		proto = curflow->detected_proto.app_protocol;
		flow->detected_proto = curflow->detected_proto;

        if (proto > NDPI_LAST_IMPLEMENTED_PROTOCOL)
            proto = NDPI_PROTOCOL_UNKNOWN;
		else {
            if (flow->detected_proto.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            /* update timeouts */
                if (debug_dpi && proto < NDPI_LAST_NFPROTO)
                	pr_info ("xt_ndpi: protocol detected %s ( dst %pI4 )\n", prot_long_str[proto], ipdst);
                flow->ndpi_timeout = t1;
                flow->detection_completed = 1;

                /* reset detection */
                if (flow->ndpi_flow) 
                    memset(flow->ndpi_flow, 0, sizeof(*(flow->ndpi_flow)));
            }
		}
	}
	kmem_cache_free (s_nf_ndpi_flow_cache, curflow);
	spin_unlock_bh (&flow_lock);

	return proto;
}


static bool check_already_checked(struct nf_conn *ct)
{
    if(!nf_ct_is_confirmed(ct)){
        struct nf_conn_ndpi *proto = nf_get_ndpi_protocol(ct);
        if(!proto){
            proto = nf_add_ndpi_protocol(ct);
            if(!proto){
                pr_err("cannot add ext ct ndpi");
                return true;
            }
            proto->checked = false;
            proto->protocol_id = 0;
        }
        if(proto){
            return proto->checked;
        }
    }
    return false;
}


unsigned int nf_ndpi_in(struct net *net, u_int8_t pf, unsigned int hooknum,		struct sk_buff *skb)
{
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;

    const struct iphdr *ip;
    const struct tcphdr *tcph;

    struct timeval tv;
    u32 proto = NDPI_PROTOCOL_UNKNOWN;
	u64 time;

    const struct sk_buff *skb_use = NULL;
    struct sk_buff *liner_skb = NULL;

    if(skb_is_nonlinear(skb)){
        liner_skb = skb_copy(skb, GFP_ATOMIC);
        if(liner_skb == NULL){
            pr_info("skb_copy failed!");
            return -1;
        }
        skb_use = liner_skb;
    }else{
        skb_use = skb;
    }

    ct = nf_ct_get (skb_use, &ctinfo);
    if(ct == NULL){
        if(liner_skb != NULL) kfree_skb(liner_skb);
        return -1;
    }
    
    if(check_already_checked(ct)){
        pr_info("check_already_checked so return");
        if(liner_skb != NULL) kfree_skb(liner_skb);
        return 0;
    }

    ip = ip_hdr(skb_use);
    tcph = (const void *)ip + ip_hdrlen(skb_use);

    do_gettimeofday(&tv);
	time = ((uint64_t) tv.tv_sec) * detection_tick_resolution 
        + tv.tv_usec / (1000000 / detection_tick_resolution);

	if(ctinfo == IP_CT_NEW){
        spin_lock_bh(&flow_lock);
        nf_ndpi_kill_flow(ct, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3,
                            &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3);
        spin_unlock_bh(&flow_lock);
	}
    proto = ndpi_process_packet(ct, time, ip_hdr(skb_use), skb_use->len, tcph);
    if(proto == NDPI_PROTOCOL_IP_ICMP){
        pr_warn("current package is icmp!");
    }
    update_protocol_to_ct(ct, proto);
    if(liner_skb != NULL) kfree_skb(liner_skb);

    return 0;
}

EXPORT_SYMBOL_GPL(nf_ndpi_in);

static void nf_ndpi_cleanup(void)
{
    struct rb_node *next;
    struct nf_ndpi_id_node *id;
    struct nf_ndpi_flow_node *flow;

    ndpi_exit_detection_module(ndpi_struct);

    next = rb_first(&s_nf_ndpi_id_root);
    while(next){
        id = rb_entry(next, struct nf_ndpi_id_node, node);
        next = rb_next(&id->node);
        rb_erase(&id->node, &s_nf_ndpi_id_root);
        kmem_cache_free(s_nf_ndpi_id_cache, id);
    }
    kmem_cache_destroy(s_nf_ndpi_id_cache);

    next = rb_first(&s_nf_ndpi_flow_root);
    while(next){
        flow = rb_entry(next, struct nf_ndpi_flow_node, node);
        next = rb_next(&flow->node);
        rb_erase(&flow->node, &s_nf_ndpi_flow_root);
        kmem_cache_free(s_nf_ndpi_flow_cache, flow);
    }
    kmem_cache_destroy(s_nf_ndpi_flow_cache);
}


static const struct nf_ct_ext_type ndpi_ext = {
    .len = sizeof(struct nf_conn_ndpi),
    .align = __alignof__(struct nf_conn_ndpi),
    .id = NF_CT_EXT_NDPI,
};


static int __init nf_ndpi_init(void)
{
    int ret = -ENOMEM;
    NDPI_PROTOCOL_BITMASK bitmask;
    int i = 0;

    pr_info("nf_ndpi_init init");

    ndpi_struct = ndpi_init_detection_module();
    if(ndpi_struct == NULL){
        return -ENOMEM;
    }

    NDPI_BITMASK_SET_ALL(bitmask);
    //NDPI_BITMASK_DEL(bitmask, 142);
 
    
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &bitmask);

    s_nf_ndpi_flow_cache = kmem_cache_create("s_nf_ndpi_flow_cache", 
                    sizeof(struct nf_ndpi_flow_node) + sizeof(struct ndpi_flow_struct),
                    0, 0, NULL);
    
    if(!s_nf_ndpi_flow_cache){
        pr_err("create s_nf_ndpi_flow_cache failed!");
        ret = -ENOMEM;
        goto ERR_NDPI_STRUCT;
    }

    s_nf_ndpi_id_cache = kmem_cache_create("s_nf_ndpi_id_cache",
                    sizeof(struct nf_ndpi_id_node) + sizeof(struct ndpi_id_struct),
                    0, 0, NULL);
    if(!s_nf_ndpi_id_cache){
        pr_err("create s_nf_ndpi_id_cache failed! ");
        ret = -ENOMEM;
        goto ERR_FLOW;
    }

    ret = nf_ct_extend_register(&ndpi_ext);
    if(ret < 0){
        pr_err("nf_ct_extend_register failed! %d", ret);
        goto ERR_ID;
    }
    
    return 0;
ERR_ID:
    kmem_cache_destroy(s_nf_ndpi_id_cache);
ERR_FLOW:
    kmem_cache_destroy(s_nf_ndpi_flow_cache);
ERR_NDPI_STRUCT:
    ndpi_exit_detection_module(ndpi_struct);

    return ret;
}

static void __exit nf_ndpi_exit(void)
{
    nf_ct_extend_unregister(&ndpi_ext);
    nf_ndpi_cleanup();
    pr_info("nf_ndpi_exit");
}


module_init(nf_ndpi_init);
module_exit(nf_ndpi_exit);
MODULE_LICENSE("GPL");

