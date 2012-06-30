/**
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version
 2 of the License, or (at your option) any later version.

 \file $Id$
 \author Fabrizio Formisano, Csaba Kiraly, Emanuele Delzeri, Simone Teofili, Francesco Mantovani
 \brief Module to interface the TFC code to the linux kernel through the handler mechanism in order to handle incoming packets.
 The module does not require SAD or SPD entries to remove the TFC header.
*/

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
MODULE_AUTHOR("Fabrizio Formisano, Csaba Kiraly, Emanuele Delzeri, Simone Teofili, Marco Giuntini, Francesco Mantovani");
MODULE_DESCRIPTION("TFC handler for incoming packets");


// call stack before we are called :
// ip_local_deliver: calling defragment
// ip_local_deliver: calling hooks
// ip_local_deliver_finish
// nh-data:-20 h-data:0
// 
// nh points to IP header (tipically -20)
// data, h points to TFC header
static int tfc_input(struct sk_buff *skb)
{
	printk(KERN_INFO "ip tfc input\n");

	tfc_remove(skb,NULL);
	
// 	if (skb->nh.iph->protocol == NEXTHDR_FRAGMENT_TFC){
// 		switch (tfc_defrag(skb)){
// 		    case NF_ACCEPT:
// 			printk(KERN_INFO "ip tfc input: packet defragd\n");
// 			return NF_STOLEN;
// 		    case NF_STOLEN:
// 			printk(KERN_INFO "ip tfc input: packet stolen for defrag\n");
// 			return NF_STOLEN;
// 		    default: 			
// 			printk(KERN_INFO "ip tfc input: ERROR\n");
// 			return 0;
// 		}
// 	}	

	//printk(KERN_INFO "ip tfc input: TFC removed, no frag. next protocol:%d\n",skb->nh.iph->protocol);
	return - skb->nh.iph->protocol;
// 	return NF_STOLEN;
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


static struct net_protocol tfc_protocol = {
	.handler	=	tfc_input,
	.err_handler	=	tfc_err,
	.no_policy	=	1,
};

static int __init tfc_init(void)
{
	printk(KERN_INFO "ip tfc_handler_in init\n");
	if (inet_add_protocol(&tfc_protocol, IPPROTO_TFC) < 0) {
		printk(KERN_INFO "ip tfc_handler_in init: can't add protocol\n");
		return -EAGAIN;
	}
	return 0;
}

static void __exit tfc_fini(void)
{
	printk(KERN_INFO "ip tfc_handler_in fini\n");
	if (inet_del_protocol(&tfc_protocol, IPPROTO_TFC) < 0)
		printk(KERN_INFO "ip tfc_handler_in close: can't remove protocol\n");
}

module_init(tfc_init);
module_exit(tfc_fini);
MODULE_LICENSE("GPL");
