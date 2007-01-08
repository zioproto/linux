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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabrizio Formisano");
MODULE_DESCRIPTION("myhook function");

static int header = 1;	//header or footer
static int prot_id = 1;	//link in with protocol id or not
static int am_hz = 1;
static int am_pktlen = 1300;


module_param(header, bool , 0644);
MODULE_PARM_DESC(header, "if 1 (default), tfc will use a heder; if 0, a footer");
module_param(prot_id, bool, 0644);
MODULE_PARM_DESC(prot_id, "if 1 (default), tfc will have its prot_id; if 0, it will be skipped (if used with header=false, it should provide some kinf of backward compatibility workaround");
module_param(am_hz, int , 0644);
MODULE_PARM_DESC(am_hz, "(default:1) packets per second");
module_param(am_pktlen, int, 0644);
MODULE_PARM_DESC(am_pktlen, "(default:1300), tfc packet size (without esp, ip, etc. header) ");

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;
struct timer_list	SAD_timer;
struct timer_list	AM_timer;
struct timeval tv;
extern void ip_send_check(struct iphdr *iph);

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
        //  static unsigned char *stolen = "\x7f\x00\x00\x01"; //127.0.0.1
	struct sk_buff *sb = *skb;
	//struct sk_buff *skb2;
	struct dst_entry *dst = sb->dst;
	struct xfrm_state *x;
	struct iphdr *iph;
	int i;
	printk(KERN_INFO "FAB myhook eseguito correttamente\n");
	iph = (struct iphdr *)sb->data;
	if (!sb->dst->xfrm) {
		printk(KERN_INFO "FAB myhook -	nessuna policy da applicare\n");
		return NF_ACCEPT;	//ipsec non applicato a questo pacchetto
	}
	
	/*Loop to search for the first ESP in the XFRM stack. */
	x = dst->xfrm;
	i = 0;
	//unsigned int free;
	do{	printk(KERN_INFO "FAB myhook - i:%d\n",i);
		i++;
//ESP->AH	if(x->id.proto == IPPROTO_ESP){
		if(x->id.proto == TFC_ATTACH_PROTO){
			printk(KERN_INFO "FAB myhook - found ESP SA, enqueue pkt\n");
			
			/*insert pkt in the SA queue*/
			//x->tfc_list.qlen++;
			//tfch_insert(sb);
			skb_queue_tail(&x->tfc_list,sb);
			printk(KERN_INFO "FAB myhook - pkt enqueued, qlen:%u\n",\
					 skb_queue_len(&x->tfc_list));
			
			return NF_STOLEN;
		}
		dst = dst->child; //scorro la catena di dst_entry
		x = dst->xfrm;
	} while (x);

	printk(KERN_INFO "FAB myhook - SA not found\n");
	return NF_ACCEPT; //abbiamo cercato su tutta la catena di dst_entry senza trovare la SA cercata
 
//	printk(KERN_INFO "FAB daddr:%x stolen addr:%x \n", sb->nh.iph->daddr, *(int*)stolen);
	
//        if (sb->nh.iph->daddr == *(int*)stolen) {
		//printk(KERN_INFO "FAB STOLEN packet to... %d.%d.%d.%d\n",
		 // 	  *stolen, *(stolen + 1),
		//	  *(stolen + 2), *(stolen + 3));
		//kfree_skb(sb);
		//okfn(sb);
/*		struct timer_container *mycontainer = \
			(struct timer_container *)kmalloc(sizeof(struct timer_container),GFP_KERNEL);
		mycontainer->skb = *skb;
		mycontainer->output = okfn;
		mycontainer->myself = mycontainer;
		init_timer(&mycontainer->timer);
		mycontainer->timer.function = myoutput;
		mycontainer->timer.data = (unsigned long)mycontainer;//->myself;
		mycontainer->timer.expires = jiffies + HZ/1000;
		add_timer(&mycontainer->timer);
*/		
		
//		return NF_STOLEN;
//              } else {
//		return NF_ACCEPT;
//              }
}



/**
build_dummy_pkt builds and equeues a dummy pkt in dummy_list, using the dummy route of the SA to route the
pkt
*/
static void build_dummy_pkt(struct xfrm_state *x){
	//x è la SA a cui è associato il traffico dummy
//	struct xfrm_state *x = (struct xfrm_state *)data;

	int i;
	//goto exit;
	/*daddr - less important byte first*/
	//printk(KERN_INFO "FAB daddr: %x\n",x->id.daddr.a4);
	/* costruisco il pacchetto dummy*/
	int len = 500;
	int header_len = MAX_HEADER;		
	struct sk_buff *skb;
	struct iphdr *iph;
	printk(KERN_INFO "FAB build_dummy_pkt\n");
	/*allocate a new skb for dummy pkt*/
	if (skb_queue_len(&x->dummy_list)<15){
		for (i = 0; i < (15 - skb_queue_len(&x->dummy_list)); i++){
			if ((skb = alloc_skb(len, GFP_ATOMIC)) == NULL) {
					NETDEBUG(KERN_INFO "FAB build_dummy_pkt - no memory for new dummy!\n");
					return;
				}
	
			skb_reserve(skb, header_len);
			//skb_put(skb,100);
			skb->nh.raw = skb_push(skb, sizeof(struct iphdr));
			iph = skb->nh.iph;
			iph->version = 4;
			iph->ihl = 5;
			iph->tos = 0;
			iph->tot_len = htons(skb->len);
			iph->frag_off = 0;
			iph->id = 0;
			iph->ttl = 200;//ip_select_ttl(inet, &rt->u.dst);
			iph->protocol = 59; /* IPPROTO_dummy in this case */
			iph->saddr = x->dummy_route->rt_src;
			iph->daddr = x->dummy_route->rt_dst;
			ip_send_check(iph);	
			//skb->priority = sk->sk_priority;
	
			skb->dst = &x->dummy_route->u.dst;
			dst_hold(skb->dst); //indica che c'è un pacchetto che sta usando quella dst
			if(skb->dst != NULL){
				//come dst utilizziamo quella costruita durante _xfrm_state_insert
				//tfch_insert(skb); 
				skb_queue_tail(&x->dummy_list,skb);
				printk(KERN_INFO "MAR dummy_pkt enqueued,dummy_qlen:%u\n",skb_queue_len(&x->dummy_list));
			}else {
				printk(KERN_INFO "FAB build_dummy_pkt - no route for pkt\n");
				kfree_skb(skb);
			}
		}
	}
}


/**
Insert TFC header and pre-padding to a pkt
To avoid kernel panic we expand the skb area of the required amount of space
This function is called in xfrm4_output.c by xfrm4_encap(), when the space for the ESP header is added: we also add a TFC header and the additional padding
KIRALY: why would you do it before queuing?
*/
//void tfch_insert(struct sk_buff *skb, int padsize, bool header, bool prot_id)
void tfch_insert(struct sk_buff *skb, int payloadsize)
{	
	struct iphdr *iph, *top_iph;
	struct ip_tfc_hdr *tfch;
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	
	iph = skb->nh.iph;
	skb->h.ipiph = iph;
	if (header) {
		pskb_expand_head(skb,sizeof(struct ip_tfc_hdr),0,GFP_ATOMIC);
		skb->nh.raw = skb_push(skb,sizeof(struct ip_tfc_hdr));
		top_iph = skb->nh.iph;
	   
		if (!x->props.mode){
			//In Transport mode
			skb->h.raw += iph->ihl*4;
			memmove(top_iph, iph, iph->ihl*4);

			//tfch should be directly before the trahsport header (h)
			tfch = skb->h.raw - sizeof(struct ip_tfc_hdr);	/*tfch è situato tra esp hdr e l'header del
 								transport layer*/
		} else {  
			//In Tunnel mode
			tfch = skb->nh.raw;
		}
	} else { // footer
		pskb_expand_head(skb,0,sizeof(struct ip_tfc_hdr),GFP_ATOMIC);
		tfch = skb_put(skb,sizeof(struct ip_tfc_hdr));
	}

	//link in TFC in the protocol "stack"
	if (prot_id) {
		if (!x->props.mode){
			//In Transport mode
			//link in TFC in the protocol "stack"
			tfch->nexthdr = skb->nh.iph->protocol;		//nexthdr=protocol originario
			skb->nh.iph->protocol = IPPROTO_TFC;
			printk(KERN_INFO "MAR tfch->nexthdr: %hhd, iph->protocol:%hhd\n", tfch->nexthdr, skb->nh.iph->protocol);
		} else {  
			//In Tunnel mode
			tfch = skb->nh.raw;
			tfch->nexthdr = IPPROTO_IPIP; //nexthd=protocol IPoverIP
		}
	}

	//tfch->padsize = htons(padsize);
	tfch->payloadsize = (u_int16_t) payloadsize;
	//skb_put(skb, tfch->padsize);		    //padding inserito dopo payload

	return;
}

/**
TFC fragmentation
*/

struct sk_buff* tfc_fragment(struct sk_buff *skb, int size)
{
	struct sk_buff *skb_new;
	printk(KERN_INFO "MAR tfc_fragment called\n");
	//struct ip_tfc_hdr *tfch, *tfch_new;
	//struct iphdr *iph;
	//struct dst_entry *dst = skb->dst;
	//struct xfrm_state *x = dst->xfrm;
	//void *tmp;
	//int new_data_len;
	//iph = skb->nh.iph;
	//u8 workbuf[60];
	skb_new = skb_clone (skb, GFP_ATOMIC);
	printk(KERN_INFO "MAR tfc_fragment - skb clonato\n");
/*
	skb_queue_tail(&x->tfc_list,skb_new);
	printk(KERN_INFO "MAR tfc_fragment - skb_new enqueued, qlen:%u\n", skb_queue_len(&x->tfc_list));
	return;*/
	
	//trim original to "size"
	skb_trim(skb, skb->len - size);

	//remove the first fragment of "size" from the remainder
	skb_pull(skb_new, size);
	
	//tmp = skb_new->data + size;
	//new_data_len = skb_new->len - size; 
	//memcpy(workbuf, skb_new->data, new_data_len);
	
	//skb_trim(skb_new,new_data_len);
	//memcpy(skb->h.raw, workbuf, new_data_len);
	//skb_trim(skb,50);	
	//tfch = skb->nh.raw + (iph->ihl*4);
	//tfch_new = skb_new->nh.raw + (iph->ihl*4);
	//tfch->frag = 2;
	//tfch->numfrag = 2;
	//tfch_new->frag = 1;
	//tfch_new->numfrag = 2;
	//skb_queue_tail(&x->tfc_list,skb_new);
	printk(KERN_INFO "MAR tfc_fragment end\n");
	return skb_new;
}

/**
KIRALY: this one is called Dequeue in architecture descripition.

KIRALY: my suggestion: give the packet size as parameter,
 do the padding, fragmentation, and possible multiplex from here!

send_pkt dequeues a pkt from the tfc queue of an ESP SA.
If no pkt is present in the queue, a dummy pkt is sent.
Moreover, before returning, the function sets the next expire for the timer
*/
/*void send_pkt(unsigned long data){
	//x è la SA a cui è associato il traffico dummy
	struct xfrm_state *x = (struct xfrm_state *)data;
*/
void dequeue(struct xfrm_state *x, int pkt_size)
{
	struct sk_buff *skb; //packet dequeued and sent
	struct sk_buff *skb_remainder; //remainder after fragmentation
	int orig_size; //original size of packet
	int padding_needed; //calculated size of padding needed
	int payload_size; //payload_size inside TFC (the rest is padding)
	
	//if pkt_size < tfc header length
	if (pkt_size < sizeof(struct ip_tfc_hdr)) {
		//error!
 		printk(KERN_INFO "KIR dequeue - requested pkt_size < ip_tfc_hdr length, skipping\n");
 		return;		
	}
	
	//select the right queue
	if (!skb_queue_empty(&x->tfc_list)) {
		skb = skb_dequeue(&x->tfc_list);	
	} else {
		//not working for tunnel at the moment
		if (x->props.mode) return;
		skb = skb_dequeue(&x->dummy_list);
		printk(KERN_INFO "MAR send_dummy_pkt -refcnt:%d\n", skb->dst->__refcnt);
		build_dummy_pkt(x);
	}

	//set packet size
	//do the padding, fragmentation, place back ...
	//to arrive to a packet of size pkt_size
	orig_size = skb->len;
	padding_needed = pkt_size - orig_size - sizeof(struct ip_tfc_hdr);
	//if padding needed
	if (padding_needed > 0) {
		//pad
		payload_size = orig_size;
		padding_insert(skb, padding_needed);
	}
	//else if fragmentation needed
	else if (padding_needed < 0) {
		//fragment
		payload_size = orig_size + padding_needed;
		skb_remainder = tfc_fragment(skb, payload_size);
		//push back remaining part
		//TODO: handle the case of dummy!
		skb_queue_head(&x->tfc_list,skb_remainder);
	} else {
		payload_size = orig_size;
	}	
        //add header
        //tfch_insert(skb,orig_size);
        tfch_insert(skb,payload_size);
		
	//send the packet
	dst_output(skb);
}

/**
main Algorithm Manager

KIRALY: suggestion:
 - handle packet size here as well, not just timing. can be a parameter of send_pkt()
 - make new timer relative to old timer, not to jiffies, to avoid clock skew
 - hadle timers per SA
*/
void Algorithm_Manager(void)
{	int i;
	struct xfrm_state *x;
	struct list_head *state_list;
	struct xfrm_state_afinfo *afinfo;
	afinfo = xfrm_state_get_afinfo(AF_INET);
	state_list = afinfo->state_bydst;

	//for each SA ???
	for (i = 0; i < XFRM_DST_HSIZE; i++) {
		//for each ???
//		printk(KERN_INFO "FAB myhook init - i:%d\n",i);
		list_for_each_entry(x, state_list+i, bydst) {
			if (x->dummy_route!=NULL) dequeue(x,am_pktlen);
		}
	}
	
	//set next timer
	init_timer(&AM_timer);
	AM_timer.expires = jiffies + HZ/am_hz;
	add_timer(&AM_timer);
}

void SA_Logic(struct xfrm_state *x)
{
	if (x->dummy_route!=NULL) dequeue(x,am_pktlen);
	init_timer(&x->tfc_alg_timer);
	x->tfc_alg_timer.expires = jiffies + HZ/10;
	add_timer(&x->tfc_alg_timer);
	
}

/**
EspTfc_SA_init creates a chain of dst_entries for the flow that belongs to this SA and saves it in an appropriate structure. We do this in order to be able to send dummy pkts on this SA regardless of the presence of data pkts.
We also initialize the tfc queue associated to the SA; this queue is used to reshape the traffic of the single SA; packets are inserted in the appropriate queue by the tfc_hook()

KIRALY: generalize max_pkt_size to an Algorith_Manager specific state variable structure!

*/
void EspTfc_SA_init(struct xfrm_state *x)
{
	/*costruisco una struttura flowi in cui inserisco l'indirizzo sorgente e destinazione 
	della SA, con cui andiamo a creare la catena di dst_entry e la salviamo in x->dummy_route
	*/
	
	printk(KERN_INFO "FAB dummy_init, SPI: %x, PROTO: %d, MODE: %u, hESP-len: %u\n",x->id.spi, x->id.proto, x->props.mode, x->props.header_len);
	//fabrizio - creo la rtable per questa SA..mi serve per poter instradare i pacchetti dummy
		struct flowi fl = { .oif = 0,
				    .nl_u = { .ip4_u =
					      { .daddr = x->id.daddr.a4,
						.saddr = x->props.saddr.a4,
						.tos = 0} },
				    .proto = IPPROTO_TFC,
		};
		int err;

		err = ip_route_output_key(&x->dummy_route, &fl);
		if (err) {
			printk(KERN_INFO "FAB dummy_init - ip_route_output_key\
				 fallito!\n");
				return;
		};
		dst_hold(&x->dummy_route->u.dst);
	// Inizializzo il valore del padding
	//x->max_pkt_size[0] = 0;
	//x->max_pkt_size[1] = 700;
	//x->max_pkt_size[2] = 1212;
	//x->max_pkt_size[3] = 1400;
	//x->max_pkt_size[4] = 1212;
	//x->max_pkt_size[5] = 1400;
	//x->s=0;

	//inizializzo la coda tfc di controllo del traffico
	skb_queue_head_init(&x->tfc_list);
	printk(KERN_INFO "MAR TFC_list init \n");
	//inizializzo la coda dei dummy
	skb_queue_head_init(&x->dummy_list);
	printk(KERN_INFO "MAR dummy_list init \n");
		build_dummy_pkt(x);
	//Inizializzo il timer di controllo dell'SA
	init_timer(&x->tfc_alg_timer);
	x->tfc_alg_timer.data = x;
	x->tfc_alg_timer.function = SA_Logic;
	x->tfc_alg_timer.expires = jiffies + HZ/10;
	add_timer(&x->tfc_alg_timer);
	return;
	
}


/**
SAD_check viene fatta partire da init e periodicamente controlla il SAD, per 
inizializzare le funzioni di TFC per ogni nuova SA ESP eventualmente inserita
*/
void SAD_check(void)
{
	printk(KERN_INFO "FAB SAD_check\n");
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
//ESP->AH			if ((x->id.proto == IPPROTO_ESP)&&(x->dummy_route == NULL)) {
				if ((x->id.proto == TFC_ATTACH_PROTO)&&(x->dummy_route == NULL)) {
					//inizializzo le funzioni di TFC per la nuova SA
					EspTfc_SA_init(x);
				}

		}
	}
	
	//ogni 15 secondi controllo nuovamente il SAD
	init_timer(&SAD_timer);
	SAD_timer.expires = jiffies + HZ*15;
	add_timer(&SAD_timer);
}




EXPORT_SYMBOL(dequeue);
EXPORT_SYMBOL(EspTfc_SA_init);
EXPORT_SYMBOL(tfch_insert);
EXPORT_SYMBOL(tfc_fragment);
//EXPORT_SYMBOL(build_padding);
//EXPORT_SYMBOL(tfc_SA_remove);
/**
ESP richiede il modulo myhook, che quindi viene caricato automaticamente all'avvio, quando le SA non sono ancora definite, per cui non è possibile inizializzare le code e i dummy;inoltre se viene aggiun ta una nuova SA, deve essere possibile inizializzare le funzioni di TFC. Soluzione:
la funzione di init avvia un timer che periodicamente controlla se ci sono nuove ESP SA e in caso affermativo esegue EspTfc_SA_init

*/
static int __init init(void)
{
	

printk(KERN_INFO "FAB myhook init\n");
/* Fill in our hook structure */
    nfho.hook = tfc_hook;         /* Handler function */
    nfho.hooknum  = NF_IP_LOCAL_OUT; /* First hook for IPv4 */
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;   /* Make our function first */

    nf_register_hook(&nfho);
	
	// start timer to periodically look for new Security Associations
	init_timer(&SAD_timer);
	SAD_timer.function = SAD_check;
	SAD_timer.expires = jiffies + HZ*15;
	add_timer(&SAD_timer);
	
/*	// Inizializzo il timer della funzione Algorithm Manager
	init_timer(&AM_timer);
	AM_timer.function = Algorithm_Manager;
	AM_timer.expires  = jiffies + HZ;
	add_timer(&AM_timer);
*/
	//spin_unlock_bh(&xfrm_state_lock);
	//wake_up(&km_waitq);


	return 0;
}

static void __exit fini(void)
{printk(KERN_INFO "FAB myhook fini\n");
	del_timer(&SAD_timer);
	//del_timer(&AM_timer);
	printk(KERN_INFO "MAR timer SAD rimosso\n");
	//to add: remove TFC queues for all SA: to do this, wait for the queue to be empty.
	nf_unregister_hook(&nfho);
}

module_init(init);
module_exit(fini);
