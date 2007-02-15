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


int tfc_input(struct sk_buff *skb)
{
	//int tfc_payloadsize;
	//struct ip_frag_hdr *fragh;
        struct ip_tfc_hdr *tfch;
	struct iphdr *iph;
	int nextprot;

	//printk(KERN_INFO "MAR myhook_in - tfc_input \n");
	iph = skb->nh.iph;
	tfch = (struct ip_tfc_hdr*) (skb->nh.raw + (iph->ihl*4));
	//fragh = (struct ip_frag_hdr*)((skb->nh.raw + (iph->ihl*4) + sizeof(struct ip_tfc_hdr)));
	//printk(KERN_INFO "RICEVUTO PACCHETTO TFC \n");

	//change protocol from TFC to the next one in iph
	nextprot = tfch->nexthdr;
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
	
	skb->nh.iph->tot_len = htons(skb->len);

	//printk(KERN_INFO "MAR - tfcrimosso iph-protocol: %d \n", skb->nh.iph->protocol);

	return nextprot;
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
	int i;

	printk(KERN_INFO "hook called: protocol:%d\n", (*skb)->nh.iph->protocol);
	printk(KERN_INFO "hook called: nh-data:%d h-data:%d\n ", (*skb)->nh.raw-(*skb)->data, (*skb)->h.raw-(*skb)->data);
	for (i=0; i<40; i++){
		printk(KERN_INFO "%x", *((*skb)->nh.raw+i));
		if ((*skb)->nh.raw+i == (*skb)->h.raw || (*skb)->nh.raw+i == (*skb)->data) printk(KERN_INFO "\n"); 
		if ((*skb)->nh.raw+i == (*skb)->tail) break; 
	}
	printk(KERN_INFO "\n");
	
	if ((*skb)->nh.iph->protocol == IPPROTO_TFC){
		printk(KERN_INFO "TFC packet received\n");
		tfc_input(*skb);
		//dst_hold((*skb)->dst);
		return NF_ACCEPT;
	}
	//dst_hold(sb->dst);
	return NF_ACCEPT;
}

int tfc_rcv(struct sk_buff *skb)
{
	int i;

	printk(KERN_INFO "hook called: protocol:%d\n", skb->nh.iph->protocol);
	printk(KERN_INFO "hook called: nh-data:%d h-data:%d\n ", skb->nh.raw-skb->data, skb->h.raw-skb->data);
	for (i=0; i<40; i++){
		printk(KERN_INFO "%x", *(skb->nh.raw+i));
		if (skb->nh.raw+i == skb->h.raw || skb->nh.raw+i == skb->data) printk(KERN_INFO "\n"); 
		if (skb->nh.raw+i == skb->tail) break; 
	}
	printk(KERN_INFO "\n");
	
	return -(tfc_input(skb));
}


static void tfc_err(struct sk_buff *skb, u32 info)
{
}

static struct net_protocol tfc_protocol = {
	.handler	=	tfc_rcv,
	.err_handler	=	tfc_err,
	.no_policy	=	1,
};


static int __init init(void)
{
	printk(KERN_INFO "EMA myhook_in init\n");
	/* Fill in our hook structure */
    	nfho.hook = tfc_hook_in;         /* Handler function */
    	nfho.hooknum  = NF_IP_LOCAL_IN; /* First hook for IPv4 */
    	nfho.pf       = PF_INET;
   	nfho.priority = NF_IP_PRI_FIRST;   /* Make our function first */

//    	nf_register_hook(&nfho);

	if (inet_add_protocol(&tfc_protocol, IPPROTO_TFC) < 0) {
		printk(KERN_INFO "ip tfc init: can't add protocol\n");
		//xfrm_unregister_type(&tfc_type, AF_INET);
		return -EAGAIN;
	}

	//skb_queue_head_init(&tfc_defrag_list);
	return 0;
}

static void __exit fini(void)
{	
	printk(KERN_INFO "EMA myhook_in fini\n");
	//nf_unregister_hook(&nfho);
	if (inet_del_protocol(&tfc_protocol, IPPROTO_TFC) < 0)
		printk(KERN_INFO "ip esp close: can't remove protocol\n");
}

module_init(init);
module_exit(fini);


