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

#include <net/tfc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabrizio Formisano, Csaba Kiraly");
MODULE_DESCRIPTION("TFC hook for outgoing packets");

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho_forward;
static struct nf_hook_ops nfho_local_out;
struct timer_list	SAD_timer;


/**
SAD_check viene fatta partire da init e periodicamente controlla il SAD, per 
inizializzare le funzioni di TFC per ogni nuova SA ESP eventualmente inserita
*/
void SAD_check(void)
{
	struct list_head *state_list;
	struct xfrm_state_afinfo *afinfo;
	int i;
	struct xfrm_state *x;

	//printk(KERN_INFO "FAB SAD_check\n");
	/*posso avere accesso alla lista del SAD solo perchè ho reso pubblica la funzione 
	xfrm_state_get_afinfo*/
	afinfo = xfrm_state_get_afinfo(AF_INET);
	state_list = afinfo->state_bydst;

	//spin_lock_bh(&xfrm_state_lock);
		
	/*we use afinfo to access the list of SAs. Afinfo has two pointers to the head of two 
	different lists, one by address and one by SPI; we can indifferently use both of them to go 
	through all the SAs. In reality xfrm uses not a single list, but an array of lists of 
	XFRM_DST_HSIZE elements, and SA are inserted in a list according to their hash value.
	We search through all the SAs inserted in the SAD, and, for all ESP SAs found, */

	for (i = 0; i < XFRM_DST_HSIZE; i++) {
//		printk(KERN_INFO "FAB myhook init - i:%d\n",i);
		list_for_each_entry(x, state_list+i, bydst) {
//			printk(KERN_INFO "FAB myhook init - entry:%d\n",x->id.proto);
//ESP->AH			if ((x->id.proto == IPPROTO_ESP)&&(x->dummy_route == NULL)) {
				if ((x->id.proto == TFC_ATTACH_PROTO)&&(x->dummy_route == NULL)) {
					//inizializzo le funzioni di TFC per la nuova SA
					EspTfc_SA_init(x);
				}

		}
	}
	
	//ogni 15 secondi controllo nuovamente il SAD
	del_timer(&SAD_timer);
	SAD_timer.expires = jiffies + HZ*15;
	add_timer(&SAD_timer);
}

void del_alg_timers(void)
{
	struct list_head *state_list;
	struct xfrm_state_afinfo *afinfo;
	int i;
	struct xfrm_state *x;

	/*posso avere accesso alla lista del SAD solo perchè ho reso pubblica la funzione 
	xfrm_state_get_afinfo*/
	afinfo = xfrm_state_get_afinfo(AF_INET);
	state_list = afinfo->state_bydst;

	//spin_lock_bh(&xfrm_state_lock);
		
	/*we use afinfo to access the list of SAs. Afinfo has two pointers to the head of two 
	different lists, one by address and one by SPI; we can indifferently use both of them to go 
	through all the SAs. In reality xfrm uses not a single list, but an array of lists of 
	XFRM_DST_HSIZE elements, and SA are inserted in a list according to their hash value.
	We search through all the SAs inserted in the SAD, and, for all ESP SAs found, */

	for (i = 0; i < XFRM_DST_HSIZE; i++) {
//		printk(KERN_INFO "FAB myhook init - i:%d\n",i);
		list_for_each_entry(x, state_list+i, bydst) {
//			printk(KERN_INFO "FAB myhook init - entry:%d\n",x->id.proto);
				if ((x->id.proto == TFC_ATTACH_PROTO)&&(x->dummy_route != NULL)) {
					//delete alg timer
					del_timer(&x->tfc_alg_timer);
					x->tfc = 0;
				}

		}
	}
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
	//printk(KERN_INFO "FAB myhook eseguito correttamente\n");
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
			//printk(KERN_INFO "FAB myhook - found ESP SA, enqueue pkt\n");
			skb_queue_tail(&x->tfc_list,sb);
			//printk(KERN_INFO "FAB myhook - pkt enqueued, qlen:%u\n", skb_queue_len(&x->tfc_list));
			return NF_STOLEN;
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
	

//printk(KERN_INFO "FAB myhook init\n");
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
