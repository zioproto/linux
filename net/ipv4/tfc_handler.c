/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <linux/pfkeyv2.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <asm/scatterlist.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <net/tfc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Delzeri Emanuele, Giuntini Marco, Csaba Kiraly");
MODULE_DESCRIPTION("TFC handler for incoming packets");

/** 
  returns 
  0: packet transformed
  -EINVAL, -ENOMEM: used by ah4 and esp4, we use it to signal stolen packet
*/
static int tfc_output(struct xfrm_state *x, struct sk_buff *skb)
{
	printk(KERN_INFO "ip tfc output\n");

	switch (tfc_apply(x,skb)){
	    case NF_ACCEPT:
		printk(KERN_INFO "ip tfc output: packet processed\n");
		return 0;
	    case NF_STOLEN:
		printk(KERN_INFO "ip tfc output: packet stolen\n");
		return -EINVAL;
	    default: 			
		printk(KERN_INFO "ip tfc output: ERROR\n");
		return 0;
	}
}

static int tfc_input(struct xfrm_state *x, struct xfrm_decap_state *decap, struct sk_buff *skb)
{
	printk(KERN_INFO "ip tfc input\n");

	tfc_remove(skb);
	if (skb->nh.iph->protocol == NEXTHDR_FRAGMENT_TFC){
		switch (tfc_defrag(skb)){
		    case NF_ACCEPT:
			printk(KERN_INFO "ip tfc input: packet defragd\n");
			return 0;
		    case NF_STOLEN:
			printk(KERN_INFO "ip tfc input: packet stolen for defrag\n");
			return -EINVAL;
		    default: 			
			printk(KERN_INFO "ip tfc input: ERROR\n");
			return 0;
		}
	}	

	printk(KERN_INFO "ip tfc input: TFC removed, no frag\n");
	return 0;
}

static void tfc_err(struct sk_buff *skb, u32 info)
{
	printk(KERN_INFO "ip tfc err\n");
}

static int tfc_init_state(struct xfrm_state *x)
{
	printk(KERN_INFO "ip tfc init_state\n");
	return 0;
}

static void tfc_destroy(struct xfrm_state *x)
{
	printk(KERN_INFO "ip tfc destroy\n");
}


static struct xfrm_type tfc_type =
{
	.description	= "TFC4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_TFC,
	.init_state	= tfc_init_state,
	.destructor	= tfc_destroy,
	.input		= tfc_input,
	.output		= tfc_output
};

static struct net_protocol tfc_protocol = {
	.handler	=	xfrm4_rcv,
	.err_handler	=	tfc_err,
	.no_policy	=	1,
};

static int __init tfc_init(void)
{
	printk(KERN_INFO "ip tfc init\n");
	if (xfrm_register_type(&tfc_type, AF_INET) < 0) {
		printk(KERN_INFO "ip tfc init: can't add xfrm type\n");
		return -EAGAIN;
	}
	if (inet_add_protocol(&tfc_protocol, IPPROTO_TFC) < 0) {
		printk(KERN_INFO "ip tfc init: can't add protocol\n");
		xfrm_unregister_type(&tfc_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

static void __exit tfc_fini(void)
{
	printk(KERN_INFO "ip tfc fini\n");
	if (inet_del_protocol(&tfc_protocol, IPPROTO_TFC) < 0)
		printk(KERN_INFO "ip tfc close: can't remove protocol\n");
	if (xfrm_unregister_type(&tfc_type, AF_INET) < 0)
		printk(KERN_INFO "ip tfc close: can't remove xfrm type\n");
}

module_init(tfc_init);
module_exit(tfc_fini);
MODULE_LICENSE("GPL");
