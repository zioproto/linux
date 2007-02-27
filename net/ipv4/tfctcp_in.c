/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/config.h>
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
#include <net/my_tfc.h>
#include <net/ah.h>
#include <linux/pfkeyv2.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <asm/scatterlist.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Delzeri Emanuele, Giuntini Marco");
MODULE_DESCRIPTION("myhook_in function");

static struct nf_hook_ops nfho;
static struct sk_buff_head tfc_defrag_list;
//static int tfc_frag_len = 0;
//static int tot_len = 0;

void tfc_input(struct sk_buff *skb)
{
	//int tfc_payloadsize;
	//struct ip_frag_hdr *fragh;
        struct ip_tfc_hdr *tfch;
	//struct iphdr *iph;
	int ihl;
	int i;

	//iph = skb->nh.iph;
	ihl = skb->nh.iph->ihl*4;
	tfch = (struct ip_tfc_hdr*) (skb->nh.raw + ihl);

	//printk(KERN_INFO "hook called: protocol:%d totlen:%d\n", skb->nh.iph->protocol, ntohs(skb->nh.iph->tot_len));
	//printk(KERN_INFO "hook called: nh-data:%d h-data:%d len:%d\n ", skb->nh.raw-skb->data, skb->h.raw-skb->data, skb->len);
	//for (i=0; i<40; i++){
	//	printk(KERN_INFO "%x", *(skb->nh.raw+i));
	//	if (skb->nh.raw+i == skb->h.raw || skb->nh.raw+i == skb->data) printk(KERN_INFO "\n"); 
	//	if (skb->nh.raw+i == skb->tail) break; 
	//}
	//printk(KERN_INFO "\n");


	//if ((skb_is_nonlinear(skb) || skb_cloned(skb)) &&
	//    skb_linearize(skb, GFP_ATOMIC) != 0) {
	//	printk(KERN_INFO "hook called: ERROR: cannot linearize!");
	//}

	//skb->ip_summed = CHECKSUM_NONE;


	//change protocol from TFC to the next one in iph	
	skb->nh.iph->protocol = tfch->nexthdr;
	//cut padding
	//pskb_trim(skb, iph->ihl*4 + sizeof(struct ip_tfc_hdr) + tfch->payloadsize);
	//save ip header in temporary work buffer

	//tfc_payloadsize = tfch->payloadsize;
	//memmove(skb->h.raw, skb->h.raw + sizeof(struct ip_tfc_hdr), tfc_payloadsize);
	//skb_trim(skb, iph->ihl*4 + tfc_payloadsize);
        
	memmove(skb->nh.raw + sizeof(struct ip_tfc_hdr), skb->nh.raw, ihl);
	skb->nh.raw = skb_pull(skb, sizeof(struct ip_tfc_hdr));
	skb->h.raw += sizeof(struct ip_tfc_hdr);
	//memcpy(skb->nh.raw, workbuf, iph->ihl*4);
	
	skb->nh.iph->tot_len = htons(skb->len);

	//printk(KERN_INFO "tfc removed: protocol:%d totlen:%d\n", skb->nh.iph->protocol, ntohs(skb->nh.iph->tot_len));
	//printk(KERN_INFO "tfc removed: nh-data:%d h-data:%d len:%d\n ", skb->nh.raw-skb->data, skb->h.raw-skb->data, skb->len);
	//for (i=0; i<40; i++){
	//	printk(KERN_INFO "%x", *(skb->nh.raw+i));
	//	if (skb->nh.raw+i == skb->h.raw || skb->nh.raw+i == skb->data) printk(KERN_INFO "\n"); 
	//	if (skb->nh.raw+i == skb->tail) break; 
	//}
	//printk(KERN_INFO "\n");

	//return skb;
}

/* This is the hook function itself.*/

unsigned int tfc_hook_in(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	if ((*skb)->nh.iph->protocol == IPPROTO_TFC){
		tfc_input(*skb);
		return NF_ACCEPT;
	}
	return NF_ACCEPT;
}

static int __init init(void)
{
	printk(KERN_INFO "EMA myhook_in init\n");
	/* Fill in our hook structure */
    	nfho.hook = tfc_hook_in;         /* Handler function */
    	nfho.hooknum  = NF_IP_LOCAL_IN; /* First hook for IPv4 */
    	nfho.pf       = PF_INET;
   	nfho.priority = NF_IP_PRI_FIRST;   /* Make our function first */

    	nf_register_hook(&nfho);

	skb_queue_head_init(&tfc_defrag_list);
	return 0;
}

static void __exit fini(void)
{	
	printk(KERN_INFO "EMA myhook_in fini\n");
	nf_unregister_hook(&nfho);
}

module_init(init);
module_exit(fini);
