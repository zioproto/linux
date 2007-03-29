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
#include <net/ip.h>

#include <net/tfc.h>
#include <linux/random.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabrizio Formisano, Kiraly Csaba");
MODULE_DESCRIPTION("myhook functions");

static int header = 1;	//header or footer
static int prot_id = 1;	//link in with protocol id or not


static int dummy = 0;
static int padding = 1;
static int fragmentation = 0;
static int multiplexing = 0;


static int delay_algorithm = 1;
static int sa_hz = 10;
static int max_queue_len = 100;//if max_queue_len=0 then queue len is not limited

static int batch_size = 1;
static int picco = 0;

static int size_algorithm = 1;
static int am_pktlen = 1300;
static int min_pktlen = 1000;
static int max_pktlen = 2000;
static int rnd_pad = 200;
int ident_frag = 0;

int a = 0;
char dummy_sent; //bool signaling that a dummy was sent, dummy queue should be refilled

static struct sk_buff_head tfc_defrag_list;
static int tfc_frag_len = 0;
static int tot_len = 0;

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
module_param(max_queue_len, int , 0644);
MODULE_PARM_DESC(max_queue_len, "if 100 (default), tfc queue len is 100 pkt ; if 0, tfc queue len is not limited");

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

//packet batching parameters
module_param(batch_size, int , 0644);
MODULE_PARM_DESC(batch_size, "(default:1) size of packets to send together");

//dummy gereneration parameters
module_param(dummy, bool, 0644);
MODULE_PARM_DESC(dummy, "(default:1), whether to use dummy packets or not");
module_param(padding, bool, 0644);
MODULE_PARM_DESC(padding, "(default:1)");
module_param(fragmentation, bool, 0644);
MODULE_PARM_DESC(fragmentation, "(default:0)");
module_param(multiplexing, bool, 0644);
MODULE_PARM_DESC(multiplexing, "(default:0)");

//struct timer_list	SAD_timer;
//extern void ip_send_check(struct iphdr *iph);


/**
build_dummy_pkt builds and queues a dummy pkt in dummy_list, using the dummy route of the SA to route the
pkt
*/
void build_dummy_pkt(struct xfrm_state *x){
	//x è la SA a cui è associato il traffico dummy
	int i;
	/*daddr - less important byte first*/
	/* costruisco il pacchetto dummy*/
	int len = 500;
	int header_len = MAX_HEADER;		
	struct sk_buff *skb;
	struct iphdr *iph;
	//printk(KERN_INFO "FAB build_dummy_pkt\n");
	/*allocate a new skb for dummy pkt*/
	if (skb_queue_len(&x->dummy_list)<15){
		for (i = 0; i < (30 - skb_queue_len(&x->dummy_list)); i++){
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
				//printk(KERN_INFO "MAR dummy_pkt enqueued,dummy_qlen:%u\n",skb_queue_len(&x->dummy_list));
			}else {
				//printk(KERN_INFO "FAB build_dummy_pkt - no route for pkt\n");
				kfree_skb(skb);
			}
		}
	}
}


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
	
	if (header) {
		if (!x->props.mode){
			//In Transport mode
			iph = skb->nh.iph;
			skb->h.ipiph = iph;
			pskb_expand_head(skb,sizeof(struct ip_tfc_hdr),0,GFP_ATOMIC);
			skb->nh.raw = skb_push(skb,sizeof(struct ip_tfc_hdr));
			top_iph = skb->nh.iph;
			
			skb->h.raw += iph->ihl*4;
			memmove(top_iph, iph, iph->ihl*4);

			//tfch should be directly before the trahsport header (h)
			tfch = (void*) skb->h.raw - sizeof(struct ip_tfc_hdr);	/*tfch è situato tra esp hdr e l'header del transport layer*/
		} else {  
			//In Tunnel mode tfc è situato tra esp hdr e ip hdr interno
			
			if ((skb->nh.raw - skb->data) == sizeof(struct ip_frag_hdr)) {//Pkt fragmented
				pskb_expand_head(skb,sizeof(struct ip_tfc_hdr),0,GFP_ATOMIC);
				skb->nh.raw = skb_push(skb,sizeof(struct ip_tfc_hdr));
				tfch = (void*) skb->nh.raw;
				tfch->nexthdr = NEXTHDR_FRAGMENT_TFC;
				
			}
			else {
				pskb_expand_head(skb,sizeof(struct ip_tfc_hdr),0,GFP_ATOMIC);
				skb->nh.raw = skb_push(skb,sizeof(struct ip_tfc_hdr));
				tfch = (void*) skb->nh.raw;
			}
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
			//printk(KERN_INFO "MAR tfch->nexthdr: %d, iph->protocol:%d\n", tfch->nexthdr, skb->nh.iph->protocol);
		} 
		else {  
			//In Tunnel
			if(tfch->nexthdr != NEXTHDR_FRAGMENT_TFC)
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
	int diff;
	struct sk_buff *skb_new;
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	struct iphdr *iph;
	struct ip_frag_hdr *fragh, *fragh_new;
	printk(KERN_INFO "MAR tfc_fragment called\n");
	if (!x->props.mode){
		iph = skb->nh.iph;
		if(skb->nh.iph->protocol != NEXTHDR_FRAGMENT_TFC){
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
			skb->nh.iph->protocol = NEXTHDR_FRAGMENT_TFC;
		
		
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
		printk(KERN_INFO "MAR fragh->nexthdr: %d, iph->protocol: %d\n", fragh->nexthdr, skb->nh.iph->protocol);
		printk(KERN_INFO "MAR fragh->nexthdr: %d, iph->protocol: %d\n", fragh_new->nexthdr, skb_new->nh.iph->protocol);
		printk(KERN_INFO "MAR tfc_fragment end\n");
	}
	else{
		diff = (skb->data - skb->nh.raw);
		printk(KERN_INFO "MAR diff: %d\n", diff);
		if(!((skb->nh.raw - skb->data) == sizeof(struct ip_frag_hdr))){
			//Inserisco l'header di frammentazione
			fragh_state = 1;
			pskb_expand_head(skb,0,sizeof(struct ip_frag_hdr),GFP_ATOMIC);
			fragh = skb_push(skb,sizeof(struct ip_frag_hdr));
			fragh->nexthdr = IPPROTO_IPIP;
		}

		headerlen = skb->data - skb->head;
		skb_new = alloc_skb(skb->end - skb->head + skb->data_len, GFP_ATOMIC);
		skb_reserve(skb_new, headerlen);
		skb_put(skb_new, skb->len - size);
		
		//Clono skb
		memcpy(skb_new->data, skb->data, sizeof(struct ip_frag_hdr));
		memmove(skb_new->data + sizeof(struct ip_frag_hdr), skb->data + sizeof(struct ip_frag_hdr) + size, skb->len - sizeof(struct ip_frag_hdr) - size);
		skb_new->dst = skb->dst;
		dst_hold(skb_new->dst);
		skb_trim(skb_new, skb->len - size);
		printk(KERN_INFO "MAR skb_new trimmed\n");
		printk(KERN_INFO "MAR len_packet_new to sent : %d\n",skb_new->len );
		fragh_new = (void*) (skb_new->data);
		skb_new->nh.raw = (void*) skb_new->data + sizeof(struct ip_frag_hdr);
		//Ridimensiono skb
		skb_trim(skb, size + sizeof(struct ip_frag_hdr));
		printk(KERN_INFO "MAR skb trimmed\n");
		printk(KERN_INFO "MAR len_packet to sent : %d\n",skb->len );
	
		//Riempio i campi header di frammentazione di skb e skb_new
		if (fragh_state == 1){  //Se il pacchetto non è stato ancora frammentato
			if (ident_frag == 255) ident_frag = 1;
			else ident_frag++;
	
			fragh->identif = ident_frag; //Riempio campo Identif di skb
			printk(KERN_INFO "MAR frag.identif = %d\n", fragh->identif);
			fragh_new->identif = ident_frag; //Riempio campo Identif di skb_new
			printk(KERN_INFO "MAR frag_new.identif = %d\n", fragh_new->identif);
			fragh->offset = 0x8000; //Riempio campo M e Offset di skb
			printk(KERN_INFO "MAR frag.offset = %x\n", fragh->offset);
			fragh_new->offset = (size & 0x7fff);	//Riempio campo M e Offset di skb_new
			printk(KERN_INFO "MAR frag_new.offset = %x\n", fragh_new->offset);
		
			printk(KERN_INFO "MAR Riempiti i campi del fragmentation header\n");
		} 
		else {                //Se il pacchetto è già stato frammentato
			fragh->offset |= 0x8000; //Riempio campo M e Offset di skb
			printk(KERN_INFO "MAR frag.offset = %x\n", fragh->offset);
			fragh_new->offset += size; //Riempio campo M e Offset di skb_new
			fragh_new->offset &= (0x7fff);
			printk(KERN_INFO "MAR frag.offset = %x\n", fragh_new->offset);
			printk(KERN_INFO "MAR Riempiti i campi del fragmentation header\n");
		} 
		printk(KERN_INFO "MAR fragh->nexthdr: %d, iph->protocol: %d\n", fragh->nexthdr, skb->nh.iph->protocol);
		diff = (skb->data - skb->nh.raw);
		printk(KERN_INFO "MAR diff: %d\n", diff);
		printk(KERN_INFO "MAR tfc_fragment end\n");	
	}
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
struct sk_buff* dequeue(struct xfrm_state *x)
{
	//select the right queue
	if (!skb_queue_empty(&x->tfc_list)) {
		//if there is a packet in the queue, take it
		dummy_sent = 0;
		return skb_dequeue(&x->tfc_list);	
	} else if (dummy && !x->props.mode) {
		//otherwise take a dummy if dummy packets are enabled
		//TODO: not working for tunnel at the moment
		dummy_sent = 1;
		return skb_dequeue(&x->dummy_list);
		//printk(KERN_INFO "MAR send_dummy_pkt -refcnt:%d\n", skb->dst->__refcnt);
	} else {
		//dummy packets are disabled
		dummy_sent = 0;
		return NULL;
	}
}

void packet_transform_len(struct xfrm_state *x, struct sk_buff *skb, int pkt_size) {
	struct sk_buff *skb_remainder; //remainder after fragmentation
	int orig_size; //original size of packet
	int padding_needed; //calculated size of padding needed
	int payload_size; //payload_size inside TFC (the rest is padding)

	if (!x->props.mode) { //Transport mode
	//calculate the size of the payload: unfortunately the skb already contains the ip header (or the pseudo header?), so we need to subtract its length
		orig_size = skb->len - skb->nh.iph->ihl*4;
	//the required padding (can be negative) is determined by the requested size, the payload_size and the tfc header size
		padding_needed = pkt_size - orig_size - sizeof(struct ip_tfc_hdr);
	}
	else { //Tunnel mode
		orig_size = skb->len;
		padding_needed = pkt_size - orig_size - sizeof(struct ip_tfc_hdr);
	}

	//look for multiplexing possibility.
	//If there is space and there are more packets in the queue, we insert the header, and go on with the next one ...

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


unsigned int tfc_remove(struct sk_buff *skb)
{
	int tfc_payloadsize;
	struct ip_frag_hdr *fragh;
        struct ip_tfc_hdr *tfch;
	struct iphdr *iph;

	printk(KERN_INFO "MAR myhook_in - tfc_input \n");
	iph = skb->nh.iph;
	tfch = (struct ip_tfc_hdr*) (skb->nh.raw + (iph->ihl*4));
	fragh = (struct ip_frag_hdr*)((skb->nh.raw + (iph->ihl*4) + sizeof(struct ip_tfc_hdr)));
	printk(KERN_INFO "RICEVUTO PACCHETTO TFC \n");
	
	skb_linearize(skb,GFP_ATOMIC); 
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
	
	skb->nh.iph->tot_len = htons(skb->len + ((void*)skb->data - (void*)skb->nh.iph));

	printk(KERN_INFO "MAR - tfcrimosso iph-protocol: %d \n", skb->nh.iph->protocol);
	
	return NF_ACCEPT;
}


static void tfc_defrag2(struct sk_buff *skb) 
{
	struct sk_buff *skb_frag;
	struct ip_frag_hdr *fragh, *fragh_new;
	struct iphdr *iph_new;
	int datalen = skb->len + ((void*)skb->data - (void*)skb->nh.iph);
	
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
	
	//printk(KERN_INFO "EMA prima del while \n");
	while (!skb_queue_empty(&tfc_defrag_list)){
		skb_frag = skb_dequeue(&tfc_defrag_list);
		fragh_new = skb_frag->nh.raw + iph_new->ihl*4;
		if((fragh_new->offset & 0x8000) == 0x8000){
			memmove(skb->data + iph_new->ihl*4 + (fragh_new->offset & 0x7fff), skb_frag->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->nh.iph) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
		}else {
			pskb_expand_head(skb, 0, skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->nh.iph) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr), GFP_ATOMIC);
			skb_put(skb, skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->nh.iph) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
			memmove(skb->data + iph_new->ihl*4 + (fragh_new->offset & 0x7fff), skb_frag->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->nh.iph) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
		}
	}
	//printk(KERN_INFO "EMA defragment accomplishied. OLE \n");
	skb->h.raw = fragh;
	//ip_send_check(iph_new);
	skb->nh.iph->tot_len = htons(skb->len + ((void*)skb->data - (void*)skb->nh.iph));
	ip_send_check(iph_new);
	return;
	
}

unsigned int tfc_defrag(struct sk_buff *sb){
 	struct ip_frag_hdr *fragh;
// 	struct sk_buff_head *code;
// 	static struct sk_buff_head skb_list;
// 	int headerlen;
	struct iphdr *iph;
	struct ip_tfc_hdr *tfch;

	tfch = (void*) sb->h.raw;
	iph = sb->nh.raw;

	//printk(KERN_INFO "EMA fragment received \n");
	fragh = (void*) sb->h.raw;
 			
	if ((fragh->offset & 0x8000) == 0x8000){ //Se M = 1
		//printk(KERN_INFO "EMA no last fragment\n");
		tfc_frag_len += sb->len + ((void*)sb->data - (void*)sb->nh.iph) - iph->ihl*4 - sizeof(struct ip_frag_hdr);
	} else {
		//printk(KERN_INFO "EMA last fragment\n");
		tot_len += fragh->offset;
	}		

	//printk(KERN_INFO "MAR myhook_in stolen packets \n");
	//return NF_STOLEN;
	//printk(KERN_INFO "EMA tfc_frag_len (a) = %d\n", tfc_frag_len);
	//printk(KERN_INFO "EMA tot_len (b) = %d\n", tot_len);
	if(tfc_frag_len == tot_len) {
		//printk(KERN_INFO "EMA total fragment\n");
		//return NF_STOLEN;
		tfc_defrag2(sb);
		tfc_frag_len = 0;
		tot_len = 0;
		//printk(KERN_INFO "EMA defragment\n");
		//printk(KERN_INFO "EMA accept\n");
		return NF_ACCEPT;
	}
	skb_queue_tail(&tfc_defrag_list, sb);
	//printk(KERN_INFO "EMA stolen\n");
	return NF_STOLEN;
}
		

/**
main SA Logic

KIRALY: suggestion:
 - handle packet size here as well, not just timing. can be a parameter of send_pkt()
 - make new timer relative to old timer, not to jiffies, to avoid clock skew
 - hadle timers per SA
*/

void SA_Logic(struct xfrm_state *x)
{
	struct sk_buff *skb = NULL;
	unsigned long	rand1;
	int modulo = 3;
	int pktlen;
	int padlen;
	unsigned long delay;
	int i;
	
	//printk(KERN_INFO "KIR SA_Logic\n");
	
	if (picco == 1){
		unsigned long	rand2;
		get_random_bytes(&rand2,4);
		int pick;
		pick = (int)rand2 % 20;
		unsigned long	rand3;
		get_random_bytes(&rand3,4);
		batch_size = (int)rand2 % 20;
		int count1;
		int count2;
		for(count1=0; count1<pick;count1++){
			for (count2=0; count2<batch_size; count2++) {
        			if (x->dummy_route!=NULL) {
					skb = dequeue(x);
					if (skb)
						dst_output(skb);
					if (dummy_sent)
						build_dummy_pkt(x);
				}
			}
		}
		get_random_bytes(&rand1,4);
		delay = HZ / (1 + (rand1%modulo));
		del_timer(&x->tfc_alg_timer);
		x->tfc_alg_timer.expires +=  delay;
		add_timer(&x->tfc_alg_timer);
	}else {
		for (i=0; i<batch_size; i++) {

			if (x->dummy_route!=NULL) {
				skb = dequeue(x);
			}

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

				//send the packet
				dst_output(skb);
	
			}
		
			//build dummies after sending the whole batch
			if (dummy_sent) {
				build_dummy_pkt(x);
			}
		}
	
		//Calcolo il # di pkt che devo inviare con l'algoritmo relativo alla SA
		switch (delay_algorithm){
			case 0:	
			case 1:	//CBR
				delay = HZ / sa_hz;
				break;
	
			case 2:	//random IPD (inter-packet-delay)
				//grometric in [0 ... 1/sa_hz sec]
				get_random_bytes(&rand1,4);
				delay = HZ / (1 + (rand1%modulo));
				break;

			case 3: //???
				delay = HZ / (1 + (a%modulo));
				a++;
				if(a>=modulo) a = 0;
				break;
		}
	
		//printk(KERN_INFO "MAR SA_Logic:%u\n", sa_hz);
		//init_timer(&x->tfc_alg_timer);
		del_timer(&x->tfc_alg_timer);
		x->tfc_alg_timer.expires +=  delay;
		add_timer(&x->tfc_alg_timer);
	}
}


/**
tfc_apply 
*/
unsigned int tfc_apply(struct xfrm_state *x,struct sk_buff *skb)
{
	if(max_queue_len != 0 && skb_queue_len(&x->tfc_list) >= max_queue_len){
		return NF_DROP;
	}
	else{
	skb_queue_tail(&x->tfc_list,skb);
    //printk(KERN_INFO "KIR skb_queue_len:%u\n", skb_queue_len(&x->tfc_list));
    	return NF_STOLEN;
	}
}


EXPORT_SYMBOL(build_dummy_pkt);
EXPORT_SYMBOL(SA_Logic);
EXPORT_SYMBOL(tfc_apply);
EXPORT_SYMBOL(tfc_remove);
EXPORT_SYMBOL(tfc_defrag);

static int __init init(void)
{
	skb_queue_head_init(&tfc_defrag_list);
	return 0;
}

static void __exit fini(void)
{
}

module_init(init);
module_exit(fini);
