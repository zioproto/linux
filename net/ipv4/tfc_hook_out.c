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

#include <net/tfc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabrizio Formisano, Csaba Kiraly");
MODULE_DESCRIPTION("TFC hook for outgoing packets");

static int tfc_in_tunnel = 1;
module_param(tfc_in_tunnel, int, 0644);
MODULE_PARM_DESC(tfc_in_tunnel, "(default:1), whether to use TFC in tunnel mode or not");


/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho_forward;
static struct nf_hook_ops nfho_local_out;
struct timer_list	SAD_timer;


/**
EspTfc_SA_init creates a chain of dst_entries for the flow that belongs to this SA and saves 
it in an appropriate structure. We do this in order to be able to send dummy pkts on this SA 
regardless of the presence of data pkts.
We also initialize the tfc queue associated to the SA; this queue is used to reshape the 
traffic of the single SA; packets are inserted in the appropriate queue by the tfc_hook()
*/
void tfc_SA_init(struct xfrm_state *x)
{

	//create_dummy_route(x);

	//Setto tfc apply a 1
	x->tfc = tfc_in_tunnel;
	//inizializzo la coda tfc di controllo del traffico
	skb_queue_head_init(&x->tfc_list);
	//printk(KERN_INFO "MAR TFC_list init \n");
	//inizializzo la coda dei dummy
	skb_queue_head_init(&x->dummy_list);
	//printk(KERN_INFO "MAR dummy_list init \n");
	//build_dummy_pkt(x);

	//Inizializzo il timer di controllo dell'SA
	init_timer(&x->tfc_alg_timer);
	x->tfc_alg_timer.data = x;
	x->tfc_alg_timer.function = SA_Logic;
	// We postpone the starup of the SA to go out of the SA earch loop. Otherwise, dummy_route creation would kill the kernel :(
	x->tfc_alg_timer.expires = jiffies + HZ;
	add_timer(&x->tfc_alg_timer);
	//printk(KERN_INFO "KIR calling SA_Logic\n");
	//SA_Logic(x);
	//printk(KERN_INFO "KIR SA_Logic finished\n");
	return;
	
}

/**
we use the callback function defined in net/xfrm.h to find the SAs:
extern int xfrm_state_walk(u8 proto, int (*func)(struct xfrm_state *, int, void*), void *);
inputs: 
    x: xfrm_state (walk will go through all the states with given protocol one after another)
    count: we don't need it
    ptr: parameters pass-through from walk. we don't need it
returns:
    0: it seems 0 is for OK.
*/
static int tfc_SA_init_cb(struct xfrm_state *x, int count, void *ptr){
    // init TFC if it wasn't yet initialized (we use dummy_route to see if it was alrady initialized or not)
    //printk(KERN_INFO "KIR tfc_SA_init_cb called\n");

    if (!(x->tfc_param.initialized)){ 
	printk(KERN_INFO "KCS calling tfc+SA_init\n");
	tfc_SA_init(x);
	x->tfc_param.initialized = true;
    }
    return 0;
}

/**
SAD_check viene fatta partire da init e periodicamente controlla il SAD, per 
inizializzare le funzioni di TFC per ogni nuova SA ESP eventualmente inserita
*/
void SAD_check(void)
{
	//Csaba: unfortunately walk dosn't work. It calls a lock, then 
	// we try to create the dummy route, which calls a policy lookup,
	// which tries to lock again ... and we go in kernel panic somehow
	xfrm_state_walk(IPPROTO_AH, tfc_SA_init_cb, NULL);

	//each 15 seconds we look for new SAs in the SAD
	//TODO: change this to callback
	del_timer(&SAD_timer);
	SAD_timer.expires = jiffies + HZ*15;
	add_timer(&SAD_timer);
}

static int del_alg_timers_cb(struct xfrm_state *x, int count, void *ptr){
    if (x->tfc_param.initialized){ 
	del_timer(&x->tfc_alg_timer);
	x->tfc = 0;
	x->tfc_param.initialized = false;
    }
    return 0;
}

void del_alg_timers(void)
{
	xfrm_state_walk(TFC_ATTACH_PROTO, del_alg_timers_cb, NULL);
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
	struct sk_buff *sb = *skb;
	struct dst_entry *dst = sb->dst;
	struct xfrm_state *x;
	struct iphdr *iph;
	int i;
	
	//printk(KERN_INFO "KCS tfc_hook_out called\n");
	iph = (struct iphdr *)sb->data;
	if (!sb->dst->xfrm) {
		//printk(KERN_INFO "FAB myhook -	nessuna policy da applicare\n");
		return NF_ACCEPT;	//ipsec non applicato a questo pacchetto
	}
	
	/*Loop to search for the first ESP in the XFRM stack. */
	x = dst->xfrm;
	i = 0;
	do{	//printk(KERN_INFO "FAB myhook - i:%d\n",i);
		i++;
//ESP->AH	if(x->id.proto == IPPROTO_ESP){
		if(x->id.proto == TFC_ATTACH_PROTO){
			//printk(KERN_INFO "FAB myhook - found SA, enqueue pkt, len:%d\n",sb->len);
			//printk(KERN_INFO "FAB myhook - pkt enqueued, qlen:%u\n", skb_queue_len(&x->tfc_list));
			return tfc_apply(x,sb);
		}
		dst = dst->child; //scorro la catena di dst_entry
		x = dst->xfrm;
	} while (x);

	//printk(KERN_INFO "FAB myhook - SA not found\n");
	return NF_ACCEPT; //abbiamo cercato su tutta la catena di dst_entry senza trovare la SA cercata
}


/**
ESP richiede il modulo myhook, che quindi viene caricato automaticamente all'avvio, quando le SA non sono ancora definite, per cui non è possibile inizializzare le code e i dummy;inoltre se viene aggiun ta una nuova SA, deve essere possibile inizializzare le funzioni di TFC. Soluzione:
la funzione di init avvia un timer che periodicamente controlla se ci sono nuove ESP SA e in caso affermativo esegue EspTfc_SA_init

*/
static int __init init(void)
{
	

	printk(KERN_INFO "KCS tfc_hook_out init\n");
	/* Fill in our hook structure */
        nfho_forward.hook = tfc_hook;         /* Handler function */
        nfho_forward.hooknum  = NF_IP_FORWARD; /* First hook for IPv4 */
        nfho_forward.pf       = PF_INET;
        nfho_forward.priority = NF_IP_PRI_FIRST;   /* Make our function first */

        nf_register_hook(&nfho_forward);

	nfho_local_out.hook = tfc_hook;         /* Handler function */
        nfho_local_out.hooknum  = NF_IP_LOCAL_OUT; /* First hook for IPv4 */
        nfho_local_out.pf       = PF_INET;
        nfho_local_out.priority = NF_IP_PRI_FIRST;   /* Make our function first */

        nf_register_hook(&nfho_local_out);
	
	// start timer to periodically look for new Security Associations
	init_timer(&SAD_timer);
	SAD_timer.function = SAD_check;
	//SAD_timer.expires = jiffies + HZ*15;
	//add_timer(&SAD_timer);
	printk(KERN_INFO "KCS calling SAD_check\n");
	SAD_check();
	return 0;
}

static void __exit fini(void)
{
	//printk(KERN_INFO "FAB myhook fini\n");
	del_timer(&SAD_timer);
	//printk(KERN_INFO "MAR timer SAD rimosso\n");
	del_alg_timers();
	nf_unregister_hook(&nfho_forward);
	nf_unregister_hook(&nfho_local_out);
}

module_init(init);
module_exit(fini);
