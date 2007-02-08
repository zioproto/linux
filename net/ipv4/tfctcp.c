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

static int header = 1;	//header or footer
static int prot_id = 1;	//link in with protocol id or not

static int dummy = 1;
static int padding = 1;
static int fragmentation = 0;
static int multiplexing = 0;

static int delay_algorithm = 1;
static int sa_hz = 1;

static int size_algorithm = 1;
static int am_pktlen = 1300;
static int min_pktlen = 1000;
static int max_pktlen = 2000;
static int rnd_pad = 200;
int ident_frag = 0;

int a = 0;
char dummy_sent; //bool signaling that a dummy was sent, dummy queue should be refilled

//TFC protocol integration parameters
module_param(header, bool , 0644);
MODULE_PARM_DESC(header, "if 1 (default), tfc will use a heder; if 0, a footer");
module_param(prot_id, bool, 0644);
MODULE_PARM_DESC(prot_id, "if 1 (default), tfc will have its prot_id; if 0, it will be skipped (if used with header=false, it should provide some kinf of backward compatibility workaround");

//packet delay parameters
module_param(delay_algorithm, int , 0644);
MODULE_PARM_DESC(delay_algorithm, "(default:1) algorithm type, default CBR");
module_param(sa_hz, int , 0644);
MODULE_PARM_DESC(sa_hz, "(default:1) packets per second");

//packet size parameters
module_param(size_algorithm, int , 0644);
MODULE_PARM_DESC(size_algorithm, "(default:1) algorithm type");
module_param(am_pktlen, int, 0644);
MODULE_PARM_DESC(am_pktlen, "(default:1300), tfc packet size (without esp, ip, etc. header) ");
module_param(min_pktlen, int, 0644);
MODULE_PARM_DESC(min_pktlen, "(default:1000), tfc packet size (without esp, ip, etc. header) ");
module_param(max_pktlen, int, 0644);
MODULE_PARM_DESC(max_pktlen, "(default:2000), tfc packet size (without esp, ip, etc. header) ");
module_param(rnd_pad, int, 0644);
MODULE_PARM_DESC(rnd_pad, "(default:200)");

//dummy gereneration parameters
module_param(dummy, bool, 0644);
MODULE_PARM_DESC(dummy, "(default:1), whether to use dummy packets or not");
module_param(padding, bool, 0644);
MODULE_PARM_DESC(padding, "(default:1)");
module_param(fragmentation, bool, 0644);
MODULE_PARM_DESC(fragmentation, "(default:0)");
module_param(multiplexing, bool, 0644);
MODULE_PARM_DESC(multiplexing, "(default:0)");

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;
struct timer_list	SAD_timer;
extern void ip_send_check(struct iphdr *iph);

// TODO: fill padding
void padding_insert(struct sk_buff *skb, int padsize)
{
	unsigned char * padding_p;
	
	//printk(KERN_INFO "MAR Tailroom: %d,\n",skb_tailroom (skb));
	pskb_expand_head(skb,0,padsize,GFP_ATOMIC);
	//printk(KERN_INFO "MAR Tailroom: %d,\n",skb_tailroom (skb));
	padding_p = skb_put(skb, padsize);	
	//printk(KERN_INFO "MAR padding_insert - padlen: %d,\n", padsize);
	
	//fill padding with 0
	memset(padding_p, 0, padsize);

	return;	
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
			tfch = (void*) skb->h.raw - sizeof(struct ip_tfc_hdr);	/*tfch è situato tra esp hdr e l'header del
 								transport layer*/
		} else {  
			//In Tunnel mode
			tfch = (void*) skb->nh.raw;
		}
	} else { // footer
		pskb_expand_head(skb,0,sizeof(struct ip_tfc_hdr),GFP_ATOMIC);
		tfch = (void*) skb_put(skb,sizeof(struct ip_tfc_hdr));
	}

	//link in TFC in the protocol "stack"
	if (prot_id) {
		if (!x->props.mode){
			//In Transport mode
			//link in TFC in the protocol "stack"
			tfch->nexthdr = skb->nh.iph->protocol;		//nexthdr=protocol originario
			skb->nh.iph->protocol = IPPROTO_TFC;
			if (am_pktlen > 1456)
			skb->nh.iph->frag_off = 0x0000;
			//printk(KERN_INFO "MAR tfch->nexthdr: %hhd, iph->protocol:%hhd\n", tfch->nexthdr, skb->nh.iph->protocol);
		} else {  
			//In Tunnel mode
			tfch = (void*) skb->nh.raw;
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
//TODO
struct sk_buff* tfc_fragment(struct sk_buff *skb, int size)
{
	int fragh_state = 0;
	int headerlen;
	struct sk_buff *skb_new;
	struct iphdr *iph;
	struct ip_frag_hdr *fragh, *fragh_new;
	printk(KERN_INFO "MAR tfc_fragment called\n");
	iph = skb->nh.iph;
	if(skb->nh.iph->protocol != NEXTHDR_FRAGMENT){
		//Inserisco l'header di frammentazione
		fragh_state = 1;
 		//iph = skb->nh.iph;
		printk(KERN_INFO "EMA skb->len before expand and put: %d \n", skb->len);
		pskb_expand_head(skb,0,sizeof(struct ip_frag_hdr),GFP_ATOMIC);
		skb_put(skb,sizeof(struct ip_frag_hdr));
		printk(KERN_INFO "EMA skb->len after expand and put: %d \n", skb->len);
		memmove(skb->data + iph->ihl*4 + sizeof(struct ip_frag_hdr), skb->data + iph->ihl*4, skb->len - iph->ihl*4 - sizeof(struct ip_frag_hdr));
		fragh = (void*) (skb->data + iph->ihl*4);
		fragh->nexthdr = skb->nh.iph->protocol;
		skb->nh.iph->protocol = NEXTHDR_FRAGMENT;
	}
	printk(KERN_INFO "EMA size frag_header: %d \n", sizeof(struct ip_frag_hdr));
	
	fragh = (void*) (skb->data + iph->ihl*4);
	headerlen = skb->data - skb->head;
	skb_new = alloc_skb(skb->end - skb->head + skb->data_len, GFP_ATOMIC);
	skb_reserve(skb_new, headerlen);
	skb_new->nh.raw = (void*) skb_new->data;
	skb_put(skb_new, skb->len - size);
	
	//Clono skb
	memcpy(skb_new->data, skb->data, (iph->ihl*4 + sizeof(struct ip_frag_hdr)));
	memmove(skb_new->data + iph->ihl*4 + sizeof(struct ip_frag_hdr), skb->data + iph->ihl*4 + sizeof(struct ip_frag_hdr) + size, skb->len - iph->ihl*4 - sizeof(struct ip_frag_hdr) - size);
	skb_new->dst = skb->dst;
	dst_hold(skb_new->dst);
	printk(KERN_INFO "EMA skb->len : %d \n", skb->len);
	
	
	fragh_new = (void*) (skb_new->data + iph->ihl*4);
	
	
	
	printk(KERN_INFO "EMA len_packet to queue : %d\n",skb_new->len );
	skb_trim(skb_new, skb->len - size);
	printk(KERN_INFO "EMA len_packet to queue : %d\n",skb_new->len );
	//Ridimensiono skb
	skb_trim(skb, size + iph->ihl*4 + sizeof(struct ip_frag_hdr));
	printk(KERN_INFO "EMA skb trimmed\n");
	printk(KERN_INFO "EMA len_packet to sent : %d\n",skb->len );
	
	//Riempio i campi header di frammentazione di skb e skb_new
	if (fragh_state == 1){  //Se il pacchetto non è stato ancora frammentato
		if (ident_frag == 255) ident_frag = 1;
		else ident_frag++;

		fragh->identif = ident_frag; //Riempio campo Identif di skb
		printk(KERN_INFO "EMA frag.identif = %d\n", fragh->identif);
		fragh_new->identif = ident_frag; //Riempio campo Identif di skb_new
		printk(KERN_INFO "EMA frag_new.identif = %d\n", fragh_new->identif);


		
		fragh->offset = 0x8000; //Riempio campo M e Offset di skb
		printk(KERN_INFO "EMA frag.offset = %x\n", fragh->offset);
		

		
		
		fragh_new->offset = (size & 0x7fff);	//Riempio campo M e Offset di skb_new
		printk(KERN_INFO "EMA frag_new.offset = %x\n", fragh_new->offset);
		
		printk(KERN_INFO "EMA Riempiti i campi del fragmentation header\n");
	} 
	else {                //Se il pacchetto è già stato frammentato
		fragh->offset |= 0x8000; //Riempio campo M e Offset di skb
		printk(KERN_INFO "EMA frag.offset = %x\n", fragh->offset);
		printk(KERN_INFO "EMA size = %d\n", size);
		fragh_new->offset += size; //Riempio campo M e Offset di skb_new
		fragh_new->offset &= (0x7fff);
		printk(KERN_INFO "EMA frag.offset = %x\n", fragh_new->offset);
		printk(KERN_INFO "EMA Riempiti i campi del fragmentation header\n");
	} 
	
	printk(KERN_INFO "MAR tfc_fragment end\n");
	return skb_new;
}

void packet_transform_len(struct xfrm_state *x, struct sk_buff *skb, int pkt_size) {
	struct sk_buff *skb_remainder; //remainder after fragmentation
	int orig_size; //original size of packet
	int padding_needed; //calculated size of padding needed
	int payload_size; //payload_size inside TFC (the rest is padding)
	//char nop; //packet size should not be changed

	//set packet size
	//do the padding, fragmentation, place back ...
	//to arrive to a packet of size pkt_size
	
	//if pkt_size < tfc header length
	//if ((padding || fragmentation || multiplexing) && pkt_size < sizeof(struct ip_tfc_hdr)) {
		//error!
 		//printk(KERN_INFO "KIR \dequeue - requested pkt_size < ip_tfc_hdr length, skipping\n");
 	//	return;		
	//}

	//calculate the size of the payload: unfortunately the skb already contains the ip header (or the pseudo header?), so we need to subtract its length
	orig_size = skb->len - skb->nh.iph->ihl*4;
	//the required padding (can be negative) is determined by the requested size, the payload_size and the tfc header size
	padding_needed = pkt_size - orig_size - sizeof(struct ip_tfc_hdr);
	//printk(KERN_INFO "KCS dequeue skb->len:%d orig_size:%d padding_needed:%d\n", skb->len, orig_size, padding_needed);
	//if padding needed
	if (padding && padding_needed > 0) {
		//pad
		payload_size = orig_size;
		padding_insert(skb, padding_needed);
	}
	//else if fragmentation needed
	else if (fragmentation && padding_needed < 0) {
		//fragment
		payload_size = orig_size + padding_needed - sizeof(struct ip_frag_hdr);
		skb_remainder = tfc_fragment(skb, payload_size);
		payload_size += sizeof(struct ip_frag_hdr);
		//push back remaining part
		//TODO: handle the case of dummy!
		skb_queue_head(&x->tfc_list,skb_remainder);
	} else {
		payload_size = orig_size;
	}	
        //add header
        //tfch_insert(skb,orig_size);
        if (padding || fragmentation || multiplexing) {
    		tfch_insert(skb,payload_size);
    	}
}

void packet_transform_pad(struct xfrm_state *x, struct sk_buff *skb, int pad_size) {
//pad size doesn't include TFC header size
	int orig_size; //original size of packet

	//calculate the size of the payload: unfortunately the skb already contains the ip header (or the pseudo header?), so we need to subtract its length
	orig_size = skb->len - skb->nh.iph->ihl*4;

	if (padding) {
		//pad
		padding_insert(skb, pad_size);
	}

        if (padding || fragmentation || multiplexing) {
    		tfch_insert(skb,orig_size);
    	}
}


void packet_transform(struct xfrm_state *x, struct sk_buff *skb)
{
	unsigned long	rand1;
	int modulo = 3;
	int pktlen;
	int padlen;
	unsigned long delay;
	
	if (skb) {
		//switch (x->size_algorithm){
		switch (size_algorithm){
			case 0:	
			case 1:	//CBR
				pktlen = am_pktlen;
				packet_transform_len(x, skb, pktlen);
				break;

			case 2:	//random size 
				//between [min_pktlen,max_pktlen]
				get_random_bytes(&rand1,4);
				pktlen = min_pktlen + rand1%(max_pktlen-min_pktlen+1) ;
				packet_transform_len(x, skb, pktlen);
				break;

			case 3:	//random padding 
				//between [0,rnd_pad]
				get_random_bytes(&rand1,4);
				padlen = rand1%(rnd_pad+1) ;
				packet_transform_pad(x, skb, padlen);
				break;
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
			//skb_queue_tail(&x->tfc_list,sb);
			//printk(KERN_INFO "FAB myhook - pkt enqueued, qlen:%u\n", skb_queue_len(&x->tfc_list));
			
			packet_transform(x,sb);

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
