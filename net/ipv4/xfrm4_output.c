/*
 * xfrm4_output.c - Common IPsec encapsulation code for IPv4.
 * Copyright (c) 2004 Herbert Xu <herbert@gondor.apana.org.au>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/compiler.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netfilter_ipv4.h>
#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/icmp.h>

//fabrizio
#include <net/my_tfc.h>
//#include <net/myhook_files.h>

/* Add encapsulation header.
 *
 * In transport mode, the IP header will be moved forward to make space
 * for the encapsulation header.
 *
 * In tunnel mode, the top IP header will be constructed per RFC 2401.
 * The following fields in it shall be filled in by x->type->output:
 *	tot_len
 *	check
 *
 * On exit, skb->h will be set to the start of the payload to be processed
 * by x->type->output and skb->nh will be set to the top IP header.
 */


static void xfrm4_encap(struct sk_buff *skb)
{	
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	struct iphdr *iph, *top_iph;	
	int flags;

	iph = skb->nh.iph;
	skb->h.ipiph = iph;
	
	skb->nh.raw = skb_push(skb, x->props.header_len);
	
	top_iph = skb->nh.iph;

	if (!x->props.mode) {
		skb->h.raw += iph->ihl*4;
		memmove(top_iph, iph, iph->ihl*4);

		return;
	}

	top_iph->ihl = 5;
	top_iph->version = 4;

	/* DS disclosed */
	top_iph->tos = INET_ECN_encapsulate(iph->tos, iph->tos);

	flags = x->props.flags;
	if (flags & XFRM_STATE_NOECN)
		IP_ECN_clear(top_iph);

	top_iph->frag_off = (flags & XFRM_STATE_NOPMTUDISC) ?
		0 : (iph->frag_off & htons(IP_DF));
	if (!top_iph->frag_off)
		__ip_select_ident(top_iph, dst, 0);

	top_iph->ttl = dst_metric(dst->child, RTAX_HOPLIMIT);

	top_iph->saddr = x->props.saddr.a4;
	top_iph->daddr = x->id.daddr.a4;
	
	//Marco
	/*In tunnel mode con TFC il campo protocol del
	  new hdr ip deve essere IPPROTO_TFC
	*/
//ESP->AH	if((x->id.proto == IPPROTO_ESP) && TFC_APPLY)
	if((x->id.proto == TFC_ATTACH_PROTO) && (x->tfc == 1))
		top_iph->protocol = IPPROTO_TFC;
	else	
		top_iph->protocol = IPPROTO_IPIP;

	memset(&(IPCB(skb)->opt), 0, sizeof(struct ip_options));
}

static int xfrm4_tunnel_check_size(struct sk_buff *skb)
{
	int mtu, ret = 0;
	struct dst_entry *dst;
	struct iphdr *iph = skb->nh.iph;
	//printk(KERN_INFO "MAR xfrm4_tunnel_check_size\n");
	if (IPCB(skb)->flags & IPSKB_XFRM_TUNNEL_SIZE)
		goto out;

	IPCB(skb)->flags |= IPSKB_XFRM_TUNNEL_SIZE;
	
	if (!(iph->frag_off & htons(IP_DF)) || skb->local_df)
		goto out;

	dst = skb->dst;
	mtu = dst_mtu(dst);
	if (skb->len > mtu) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		ret = -EMSGSIZE;
	}
out:
	return ret;
}

static int xfrm4_output_one(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	int err;
	int counter;

	//fabrizio
	//printk(KERN_INFO "FAB xfrm4_output_one - header_len:%d, LL:%d,headroom:%d\n",x->props.header_len,LL_RESERVED_SPACE(skb->dst->dev),skb_headroom(skb) );
	
	if (skb->ip_summed == CHECKSUM_HW) {
		err = skb_checksum_help(skb, 0);
		if (err)
			goto error_nolock;
	}

	if (x->props.mode) {
		err = xfrm4_tunnel_check_size(skb);
		if (err)
			goto error_nolock;
	}

	counter = 1;
	do {
		spin_lock_bh(&x->lock);
		err = xfrm_state_check(x, skb);
		if (err)
			goto error;
		//fabrizio
		//printk(KERN_INFO "FAB xfrm4_output_one - call xfrm4_encap %d\n",counter);
		xfrm4_encap(skb);
		counter++;
		//fabrizio
		//printk(KERN_INFO "FAB xfrm4_output_one - call x->type->output\n");
		err = x->type->output(x, skb);
		if (err)
			goto error;

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock_bh(&x->lock);
	
		if (!(skb->dst = dst_pop(dst))) { //dst_pop restituisce dst->child
			err = -EHOSTUNREACH;
			goto error_nolock;
		}
		dst = skb->dst; //in questo modo andiamo a chiamare i metodi output di tutta la catena xfrm
		x = dst->xfrm;
	} while (x && !x->props.mode);

	IPCB(skb)->flags |= IPSKB_XFRM_TRANSFORMED;
	err = 0;

out_exit:
	return err;
error:
	spin_unlock_bh(&x->lock);
error_nolock:
	kfree_skb(skb);
	goto out_exit;
}

static int xfrm4_output_finish(struct sk_buff *skb)
{
 	int err;
	int counter;

	//fabrizio
	//printk(KERN_INFO "FAB xfrm4_output_finish\n");

#ifdef CONFIG_NETFILTER
	if (!skb->dst->xfrm) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		//fabrizio
		//printk(KERN_INFO "FAB xfrm4_output_finish - return dst_output(skb)\n");
		
		return dst_output(skb);
	}
#endif  

	counter = 1;
	while (likely((err = xfrm4_output_one(skb)) == 0)) {
		nf_reset(skb);
		//fabrizio
		
		//printk(KERN_INFO "FAB xfrm4_output_finish - HOOK: LOCAL_OUT %d,(dst_output mai eseguita)\n",counter);
		err = nf_hook(PF_INET, NF_IP_LOCAL_OUT, &skb, NULL,
			      skb->dst->dev, dst_output);
		//printk(KERN_INFO "FAB xfrm4_output_finish - HOOK: LOCAL_OUT END %d\n", counter);
		counter++;
		
		if (unlikely(err != 1))
			break;

		if (!skb->dst->xfrm) {
			//fabrizio
			//printk(KERN_INFO "FAB xfrm4_output_finish -last dst of the chain - return dst_output(skb)\n");
			return dst_output(skb);
		}
		//fabrizio
		//printk(KERN_INFO "FAB xfrm4_output_finish - HOOK: POST_ROUTING - xfrm4_output_finish mai eseguito!\n");
		
		err = nf_hook(PF_INET, NF_IP_POST_ROUTING, &skb, NULL,
			      skb->dst->dev, xfrm4_output_finish);
		
		if (unlikely(err != 1))
			break;
	}

	return err;
}

int xfrm4_output(struct sk_buff *skb)
{	//fabrizio
	//printk(KERN_INFO "FAB xfrm4_output - HOOK_COND: POST_ROUTING - esegui xfrm4_output_finish\n");

	return NF_HOOK_COND(PF_INET, NF_IP_POST_ROUTING, skb, NULL, skb->dst->dev,
			    xfrm4_output_finish,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}
