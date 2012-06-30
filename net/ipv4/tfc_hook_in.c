/**
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version
 2 of the License, or (at your option) any later version.

 \file $Id$
 \author Fabrizio Formisano, Csaba Kiraly, Emanuele Delzeri, Simone Teofili, Francesco Mantovani
 \brief Module to interface the TFC code to the linux kernel through the Netfilter hook mechanism.
*/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <asm/param.h> 
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/pfkeyv2.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <asm/scatterlist.h>

#include <net/tfc.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Delzeri Emanuele, Giuntini Marco, Csaba Kiraly");
MODULE_DESCRIPTION("TFC hook for incoming packets");

static struct nf_hook_ops nfho;

//static struct sk_buff_head tfc_defrag_list;
//static int tfc_frag_len = 0;
//static int tot_len = 0;

/* This is the hook function itself.*/
unsigned int tfc_hook_in(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sb = *skb;

	//printk(KERN_INFO "KCS tfc_hook_in called : protocol: %d\n", iph->protocol);
	
	if (sb->nh.iph->protocol == IPPROTO_TFC){
		printk(KERN_INFO "KCS tfc_hook_in: protocol ip : %d \n", sb->nh.iph->protocol);
// 		tfc_remove(sb);
		if (sb->nh.iph->protocol == NEXTHDR_FRAGMENT_TFC){
			printk(KERN_INFO "KCS tfc_hook_in fragmentation\n");
// 			return tfc_defrag(sb, x);
		}	
	}

	//printk(KERN_INFO "MAR myhook_in : no tfc packet ip protocol: %d\n", iph->protocol);
	//dst_hold(sb->dst);
	return NF_ACCEPT;
}

static int __init init(void)
{
	printk(KERN_INFO "EMA tfc_hook_in init\n");
	/* Fill in our hook structure */
    	nfho.hook = tfc_hook_in;         /* Handler function */
    	nfho.hooknum  = NF_IP_LOCAL_IN; /* First hook for IPv4 */
    	nfho.pf       = PF_INET;
   	nfho.priority = NF_IP_PRI_FIRST;   /* Make our function first */

    	nf_register_hook(&nfho);

	//skb_queue_head_init(&tfc_defrag_list);
	return 0;


}


static void __exit fini(void)
{	
	printk(KERN_INFO "EMA tfc_hook_in fini\n");
	nf_unregister_hook(&nfho);
}

module_init(init);
module_exit(fini);

