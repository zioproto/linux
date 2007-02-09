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
static int tfc_frag_len = 0;
static int tot_len = 0;



void tfc_input(struct sk_buff *skb)
{
	
	
	//int tfc_payloadsize;
	//struct ip_frag_hdr *fragh;
        struct ip_tfc_hdr *tfch;
	struct iphdr *iph;

	//printk(KERN_INFO "MAR myhook_in - tfc_input \n");
	iph = skb->nh.iph;
	tfch = (struct ip_tfc_hdr*) (skb->nh.raw + (iph->ihl*4));
	//fragh = (struct ip_frag_hdr*)((skb->nh.raw + (iph->ihl*4) + sizeof(struct ip_tfc_hdr)));
	//printk(KERN_INFO "RICEVUTO PACCHETTO TFC \n");

	//change protocol from TFC to the next one in iph	
	skb->nh.iph->protocol = tfch->nexthdr;
	//cut padding
	//pskb_trim(skb, iph->ihl*4 + sizeof(struct ip_tfc_hdr) + tfch->payloadsize);
	//save ip header in temporary work buffer

	//tfc_payloadsize = tfch->payloadsize;
	//memmove(skb->h.raw, skb->h.raw + sizeof(struct ip_tfc_hdr), tfc_payloadsize);
	//skb_trim(skb, iph->ihl*4 + tfc_payloadsize);
        
	skb->h.raw = skb_pull(skb, sizeof(struct ip_tfc_hdr));
	//skb->nh.raw += sizeof(struct ip_tfc_hdr);
	//memcpy(skb->nh.raw, workbuf, iph->ihl*4);
	
	//skb->nh.iph->tot_len = htons(skb->len);

	printk(KERN_INFO "MAR - tfcrimosso iph-protocol: %d \n", skb->nh.iph->protocol);

	//return skb;
}

/* This is the hook function itself.*/

unsigned int tfc_hook_in(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	//struct sk_buff *sb = *skb;
	//struct iphdr *iph;
	//struct ip_tfc_hdr *tfch;
 	//struct ip_frag_hdr *fragh;
	//tfch = (void*) sb->h.raw;
	//iph = sb->nh.raw;


	if ((*skb)->nh.iph->protocol == IPPROTO_TFC){
		tfc_input(*skb);
		//dst_hold((*skb)->dst);
		return NF_ACCEPT;
	}

	//dst_hold(sb->dst);
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
