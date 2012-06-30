/**
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version
 2 of the License, or (at your option) any later version.

 \file $Id$
 \author 
 \brief Module to interface the TFC code to the linux kernel through the handler mechanism.
 The module registers in the IP stack (inet_add_protocol) 
 as a handler for the TFC protocol in order to handlee incoming TFC PDUs.
 For outgoing packets receive TFC treatment, the module registers with
 the XFRM framework (xfrm_register_type). A packet receives a TFC header
 if matching TFC SP and SA are present.
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
MODULE_DESCRIPTION("TFC handler");

static int tfc_in_tunnel = 1;
/** 
  returns 
  0: packet transformed
  -EINVAL, -ENOMEM: used by ah4 and esp4, we use it to signal stolen packet
*/
static int tfc_output(struct xfrm_state *x, struct sk_buff *skb)
{
// 	struct rtable *rth;
// 	struct dst_entry *dst;
	//printk(KERN_INFO "ip tfc output\n");
// 	skb_queue_tail(&x->tfc_list,skb);
// 	skb = dequeue(x);
// 	packet_transform_len(x, skb, x->tfc_param.am_pktlen);
// 	return 0;
	switch (tfc_apply(x,skb)){
	    case NF_ACCEPT:
		//printk(KERN_INFO "ip tfc output: packet processed\n");
		return 0;
	    case NF_STOLEN:
		//printk(KERN_INFO "ip tfc output: packet stolen\n");
// 		IPCB(skb)->flags |= IPSKB_REROUTED;
// 		dst->output = NF_STOLEN;
// 		dst_release(skb->dst);
// 		skb->dst->output = 0;
		return NF_STOLEN;
	    default: 			
		printk(KERN_INFO "ip tfc output: ERROR\n");
		return 0;
	}
}


/// Receive packet with TFC header, remove the header and 
/// decide whether it should be delayed (if fragment).
/// Assumptions: 
///  nh point to IP header (otside of data area)
///  data points to TFC header
///  h points to TFC header
static int tfc_input(struct xfrm_state *x, struct sk_buff *skb)
{
	struct iphdr *iph;
	printk(KERN_INFO "tfc_input\n");
	iph = ip_hdr(skb);
	WARN_ON(iph->protocol != IPPROTO_TFC);
	WARN_ON(skb->network_header + ip_hdr(skb)->ihl*4 != skb->transport_header);
	//WARN_ON(skb->network_header != skb->data);
	
	//remove tfc header and padding
	if  (tfc_remove(skb,x) != NF_ACCEPT) {
		printk(KERN_INFO "tfc_input: error from tfc_remove\n");
		return -EINVAL;
	}

	//WARN_ON(skb->nh.raw + skb->nh.iph->ihl*4 != skb->h.raw);
	//WARN_ON(skb->h.raw != skb->data);
	
	//remove fragmentation
	if (iph->protocol == NEXTHDR_FRAGMENT_TFC){
		//set skb->data to point to IP header
		//somhow defrag has this "interface"
		//TODO: remove this requirement
		skb_push(skb, skb->data - skb->network_header);
		
		switch (tfc_defrag(skb, x)){
			case NF_ACCEPT:
				// packet reassambled, we can send it on 
				break;
			case NF_STOLEN:
				// more fragments needed
				return NF_STOLEN;
			default: 			
				printk(KERN_INFO "tfc_input: error from tfc_defrag\n");
				return 0;
		}
		//reset skb->data to point to the internal header
		//TODO: remove this requirement
		skb_pull(skb, skb->transport_header - skb->data);
	}

	switch (x->props.mode) {
	    case XFRM_MODE_TRANSPORT:
		// set pointers as requested by xfrm4_transport_input (description copied here)
		/*
		 * The IP header will be moved over the top of the encapsulation header.
		 * On entry, skb->h shall point to where the IP header should be and skb->nh
		 * shall be set to where the IP header currently is.  skb->data shall point
		 * to the start of the payload.
		 */

		//skb->nh points to the IP header, should already be OK
		//skb->data points to the payload, should already be OK
		//skb->h points to the payload, we should move this
		
		skb->transport_header = skb->network_header; /*Otherwise xfrm4_mode_transport.c function xfrm4_transport_input :	
								if (skb->transport_header != skb->network_header) {
								   memmove(skb_transport_header(skb),skb_network_header(skb), ihl);
								   skb->network_header = skb->transport_header;
								   }*/


		//WARN_ON(skb->transport_header != skb->data);
		//WARN_ON(skb->network_header + ip_hdr(skb)->ihl*4 != skb->transport_header);
		//skb->h.raw -= skb->nh.iph->ihl*4;
		break;
		
	    case XFRM_MODE_TUNNEL:
		//it seems that skb->nh should point to the external IP header
		//skb->h should point to the internal IP header, and 
		//this is what we have :)
		WARN_ON(skb->network_header + ip_hdr(skb)->ihl*4 != skb->transport_header);
		WARN_ON(skb->transport_header != skb->data);
		break;
	    default:
		NETDEBUG(KERN_INFO "unnknown XFRM MODE, hoping pointers are alrady set correctly!\n");
	}


	return 0;
}

static void tfc_err(struct sk_buff *skb, u32 info)
{
	printk(KERN_INFO "ip tfc err\n");
}

static int tfc_init_state(struct xfrm_state *x)
{
	printk(KERN_INFO "ip tfc init_state\n");
	//Setto tfc apply a 1
	x->tfc = tfc_in_tunnel;
	skb_queue_head_init(&x->tfc_defrag_list);

	//initialize the tfc queue
	skb_queue_head_init(&x->tfc_list);

	//initialize the dummy queue (it will only be filled later, we can't do it here, otherwise XFRM would die)
	if (x->tfc_param.dummy)
	skb_queue_head_init(&x->dummy_list);

	//Inizialize SA timer
	init_timer(&x->tfc_alg_timer);
	x->tfc_alg_timer.data = (unsigned long) x;
	x->tfc_alg_timer.function = (void*) SA_Logic;
	// We postpone the starup of the SA. Otherwise, dummy_route creation would kill the kernel :(
	x->tfc_alg_timer.expires = jiffies + HZ;
	add_timer(&x->tfc_alg_timer);
	
	// FRANCESCO:inizializzo i nuovi paramentri che ho aggiunto in tfcparameters 
	x->tfc_param.dummy_sent=0;
	x->tfc_param.ident_frag=0;
	x->tfc_param.tfc_frag_len=0;
	x->tfc_param.tot_len=0;
	x->tfc_param.counter=0;
	x->tfc_param.stima=0;
	x->tfc_param.stima_old=0;
	x->tfc_param.trigger_counter=0;
	x->tfc_param.flag=0;
	// FINE FRANCESCO
	
	//Set the header length. The framework uses this for two things: 1, MTU calculation 2, to reserve header space before colling our output
	//We do not the size of the frag hdr here, since it is optional, and it should not be a problem for the MTU since we fragment only if we reduce the size 
	x->props.header_len = sizeof(struct ip_tfc_hdr);
	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct iphdr);
	
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
