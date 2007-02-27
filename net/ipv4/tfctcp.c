/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
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

#include <net/my_tfc.h>
#include <linux/random.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabrizio Formisano");
MODULE_DESCRIPTION("myhook function");

//int a = 0;
//char dummy_sent; //bool signaling that a dummy was sent, dummy queue should be refilled

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;
//struct timer_list	SAD_timer;
extern void ip_send_check(struct iphdr *iph);


/**
Insert TFC header and pre-padding to a pkt
To avoid kernel panic we expand the skb area of the required amount of space
This function is called in xfrm4_output.c by xfrm4_encap(), when the space for the ESP header is added: we also add a TFC header and the additional padding
KIRALY: why would you do it before queuing?
*/
//void tfch_insert(struct sk_buff *skb, int padsize, bool header, bool prot_id)
void tfch_insert(struct sk_buff *skb)
{	
	struct iphdr *old_iph;
	// *top_iph;
	struct ip_tfc_hdr *tfch;
	//struct dst_entry *dst = skb->dst;
	//struct xfrm_state *x = dst->xfrm;
	int ihl;
	
	printk(KERN_INFO "tfch_insert: skb->len:%d headroom:%d, tailroom:%d\n", skb->len, skb_headroom(skb), skb_tailroom(skb));

	ihl = skb->nh.iph->ihl*4;
	old_iph = skb->nh.iph;
	//skb->h.ipiph = iph;

		//pskb_expand_head(skb,sizeof(struct ip_tfc_hdr),0,GFP_ATOMIC);
	//extend skb to make space for TFC, store new "nh"
	skb->nh.raw = skb_push(skb,sizeof(struct ip_tfc_hdr));
		//top_iph = skb->nh.iph;
	   
			//skb->h.raw += iph->ihl*4;
	memmove(skb->nh.iph, old_iph, ihl);

			//tfch should be directly before the trahsport header (h)
	tfch = (void*) skb->h.raw - sizeof(struct ip_tfc_hdr);	/*tfch è situato tra esp hdr e l'header del
 								transport layer*/
	//printk(KERN_INFO "tfch_insert: skb->len:%d tfc_payloadsize:%d, iph->tot_len:%d\n", skb->len, tfc_payloadsize, ntohs(skb->nh.iph->tot_len));
	printk(KERN_INFO "tfch_insert: skb->len:%d data-nh:%d, data-h:%d\n", skb->len, skb->data-skb->nh.raw, skb->data-skb->h.raw);
	//link in TFC in the protocol "stack"

			//In Transport mode
			//link in TFC in the protocol "stack"
	tfch->nexthdr = skb->nh.iph->protocol;		//nexthdr=protocol originario
	skb->nh.iph->protocol = IPPROTO_TFC;
			//if (am_pktlen > 1456)
			//skb->nh.iph->frag_off = 0x0000;
			//printk(KERN_INFO "MAR tfch->nexthdr: %hhd, iph->protocol:%hhd\n", tfch->nexthdr, skb->nh.iph->protocol);

	//set ip length field
	skb->nh.iph->tot_len = htons(skb->len);

	ip_send_check(skb->nh.iph);

	return;
}

/* This is the hook function itself.
   Check if there are related XFRMs. If no, return accept.
   Search for the first ESP in the XFRM stack. 
   If found, steal the packet and put it in the queue of that XFRM */
unsigned int tfc_hook(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
	
	/* IP address we want to drop packets from, in NB order */
        //struct sk_buff **nskb,
	//struct sk_buff *sb = *skb;
	struct dst_entry *dst = (*skb)->dst;
	struct xfrm_state *x;
	//struct iphdr *iph;
	int i;
	//printk(KERN_INFO "FAB myhook eseguito correttamente\n");
	//iph = (struct iphdr *)sb->data;
	if (!dst->xfrm) {
		//printk(KERN_INFO "FAB myhook -	nessuna policy da applicare\n");
		return NF_ACCEPT;	//ipsec non applicato a questo pacchetto
	}
	
	/*Loop to search for the first ESP in the XFRM stack. */
	x = dst->xfrm;
	i = 0;
	do{
		i++;
		if(x->id.proto == TFC_ATTACH_PROTO){
			//printk(KERN_INFO "FAB myhook - found ESP SA, enqueue pkt\n");
			//skb_queue_tail(&x->tfc_list,sb);
			//printk(KERN_INFO "FAB myhook - pkt enqueued, qlen:%u\n", skb_queue_len(&x->tfc_list));
			
			//*skb  = skb_copy(*skb,GFP_ATOMIC);
			//if ((skb_is_nonlinear(*skb) || skb_cloned(*skb)) && skb_linearize(*skb, GFP_ATOMIC) != 0) {
			//	printk(KERN_INFO "TFC hook: error linearizing\n");
			//}
						
			tfch_insert(*skb);

			return NF_ACCEPT;
		}
		dst = dst->child; //scorro la catena di dst_entry
		x = dst->xfrm;
	} while (x);

	//printk(KERN_INFO "FAB myhook - SA not found\n");
	return NF_ACCEPT; //abbiamo cercato su tutta la catena di dst_entry senza trovare la SA cercata
}

static int __init init(void)
{
//printk(KERN_INFO "FAB myhook init\n");
/* Fill in our hook structure */
        nfho.hook = tfc_hook;         /* Handler function */
        nfho.hooknum  = NF_IP_LOCAL_OUT; /* First hook for IPv4 */
        nfho.pf       = PF_INET;
        nfho.priority = NF_IP_PRI_FIRST;   /* Make our function first */

        nf_register_hook(&nfho);
	
	return 0;
}

static void __exit fini(void)
{
	//printk(KERN_INFO "FAB myhook fini\n");
	nf_unregister_hook(&nfho);
}

module_init(init);
module_exit(fini);
