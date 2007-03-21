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
// static struct hlist_head tfc_fragment_head;
// static LIST_HEAD(tfc_frag_lru_list);
// int tfc_frag_nqueues = 0;
// static struct tfc_frag_queue {
// 
// 	struct hlist_node list;
// 	struct list_head lru_list;
// 	__u8 id;
// 	__u32 saddr;
// 	__u32 daddr;
// 	struct timer_list timer;
// 	struct sk_buff *fragments;
// };

static struct sk_buff_head tfc_defrag_list;
static int tfc_frag_len = 0;
static int tot_len = 0;



static struct sk_buff* tfc_input(struct sk_buff *skb)
{
	
	
	//u8 workbuf[60];
	int tfc_payloadsize;
	struct ip_frag_hdr *fragh;
        struct ip_tfc_hdr *tfch;
	struct iphdr *iph;

	printk(KERN_INFO "MAR myhook_in - tfc_input \n");
	iph = skb->nh.iph;
	tfch = (struct ip_tfc_hdr*) (skb->nh.raw + (iph->ihl*4));
	fragh = (struct ip_frag_hdr*)((skb->nh.raw + (iph->ihl*4) + sizeof(struct ip_tfc_hdr)));
	printk(KERN_INFO "RICEVUTO PACCHETTO TFC \n");

	//change protocol from TFC to the next one in iph	
	skb->nh.iph->protocol = tfch->nexthdr;
	//cut padding
	//pskb_trim(skb, iph->ihl*4 + sizeof(struct ip_tfc_hdr) + tfch->payloadsize);
	//save ip header in temporary work buffer
	tfc_payloadsize = tfch->payloadsize;
	memmove(skb->h.raw, skb->h.raw + sizeof(struct ip_tfc_hdr), tfc_payloadsize);
	skb_trim(skb, iph->ihl*4 + tfc_payloadsize);
        
	//skb->h.raw = skb_pull(skb, sizeof(struct ip_tfc_hdr));
	//skb->nh.raw += sizeof(struct ip_tfc_hdr);
	//memcpy(skb->nh.raw, workbuf, iph->ihl*4);
	
	skb->nh.iph->tot_len = htons(skb->len);

	printk(KERN_INFO "MAR - tfcrimosso iph-protocol: %d \n", skb->nh.iph->protocol);

	return skb;
}


static void tfc_defrag(struct sk_buff *skb) 
{
	struct sk_buff *skb_frag;
	struct ip_frag_hdr *fragh, *fragh_new;
	struct iphdr *iph_new;
	int datalen = skb->len;
	
	//skb_reserve(skb, 20);
	//skb_push(skb, 20);
	//skb_put(skb, tot_len); 
	//skb->nh.raw = (void*) skb->data;
	iph_new = skb->nh.iph;
	fragh = skb->nh.raw + iph_new->ihl*4;
	iph_new->protocol = fragh->nexthdr;
	pskb_expand_head(skb, 0, tfc_frag_len - sizeof(struct ip_frag_hdr), GFP_ATOMIC);
	skb_put(skb, tfc_frag_len - sizeof(struct ip_frag_hdr));
	memmove(skb->data + iph_new->ihl*4 + ((fragh->offset) & 0x7fff), skb->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), datalen - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
	
	printk(KERN_INFO "EMA prima del while \n");
	while (!skb_queue_empty(&tfc_defrag_list)){
		skb_frag = skb_dequeue(&tfc_defrag_list);
		fragh_new = skb_frag->nh.raw + iph_new->ihl*4;
		if((fragh_new->offset & 0x8000) == 0x8000){
			memmove(skb->data + iph_new->ihl*4 + (fragh_new->offset & 0x7fff), skb_frag->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), skb_frag->len - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
		}else {
			pskb_expand_head(skb, 0, skb_frag->len - iph_new->ihl*4 - sizeof(struct ip_frag_hdr), GFP_ATOMIC);
			skb_put(skb, skb_frag->len - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
			memmove(skb->data + iph_new->ihl*4 + (fragh_new->offset & 0x7fff), skb_frag->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), skb_frag->len - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
		}
	}
	printk(KERN_INFO "EMA defragment accomplishied. OLE \n");
	skb->h.raw = fragh;
	ip_send_check(iph_new);
	skb->nh.iph->tot_len = skb->len;
	//ip_send_check(iph_new);
	return;
	
}


/* This is the hook function itself.*/

unsigned int tfc_hook_in(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sb = *skb;
	//struct sk_buff *skb_new;
	//struct dst_entry *dst = sb->dst;
	//struct xfrm_state *x;
	struct iphdr *iph;
	struct ip_tfc_hdr *tfch;
 	struct ip_frag_hdr *fragh;
// 	struct sk_buff_head *code;
// 	static struct sk_buff_head skb_list;
// 	int headerlen;
	tfch = (void*) sb->h.raw;
	iph = sb->nh.raw;


	if (sb->nh.iph->protocol == IPPROTO_TFC){
		printk(KERN_INFO "EMA protocol ip : %d \n", sb->nh.iph->protocol);
		//skb_trim(sb, iph->ihl*4 + tfch->payloadsize);
		sb = tfc_input(sb);
		if (sb->nh.iph->protocol == NEXTHDR_FRAGMENT_TFC){
			printk(KERN_INFO "EMA fragment received \n");
			fragh = (void*) sb->h.raw;
 			
			if ((fragh->offset & 0x8000) == 0x8000){ //Se M = 1
				printk(KERN_INFO "EMA no last fragment\n");
				tfc_frag_len += sb->len - iph->ihl*4 - sizeof(struct ip_frag_hdr);
			} 
			else {
				printk(KERN_INFO "EMA last fragment\n");
				tot_len += fragh->offset;
			}		
// 			printk(KERN_INFO "MAR myhook_in stolen packets \n");
// 			return NF_STOLEN;
			printk(KERN_INFO "EMA tfc_frag_len (a) = %d\n", tfc_frag_len);
			printk(KERN_INFO "EMA tot_len (b) = %d\n", tot_len);
			if(tfc_frag_len == tot_len) {
				printk(KERN_INFO "EMA total fragment\n");
				//return NF_STOLEN;
				tfc_defrag(sb);
				tfc_frag_len = 0;
				tot_len = 0;
				printk(KERN_INFO "EMA defragment\n");
				printk(KERN_INFO "EMA accept\n");
				return NF_ACCEPT;
			}
			skb_queue_tail(&tfc_defrag_list, sb);
			printk(KERN_INFO "EMA stolen\n");
			return NF_STOLEN;
		}
		//dst_hold(sb->dst);
		printk(KERN_INFO "EMA no fragmentation: accept\n");
		return NF_ACCEPT;
	}

	printk(KERN_INFO "MAR myhook_in : no tfc packet ip protocol: %d\n", iph->protocol);
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
