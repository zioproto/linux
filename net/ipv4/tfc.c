/**
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version
 2 of the License, or (at your option) any later version.

 \file $Id$
 \author Csaba Kiraly, Fabrizio Formisano, Emanuele Delzeri, Simone Teofili, Francesco Mantovani
 \brief Core Traffic Flow Confidentiality (TFC) functionality.
 Implement the core module of TFC system.
 Here you find the TFC time algorithm and size pattern and elementary function devoleped for it.
 It's supposed that a xfrm_state is passed to Sa_logic, the main function
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
MODULE_AUTHOR("Csaba Kiraly, Fabrizio Formisano, Emanuele Delzeri, Simone Teofili, Francesco Mantovani");
MODULE_DESCRIPTION("Traffic Flow Confidentiality");

// brief explanation of TFC variables:
/* in file include/linux/xfrm.h there is the struct:
struct tfcparameters {
	__u32			delay_algorithm;
	__u32			saddr_dummy;
	__u32			daddr_dummy;
	__u32 			tfc;
	__u32 			header;
	__u32			prot_id;
	__u32			dummy;
	__u32 			padding;
	__u32			fragmentation;
	__u32			multiplexing;
	__u32			sa_hz;
	__u32			max_queue_len;
	__u32			batch_size;
	__u32			picco;
	__u32			size_algorithm;
	__u32			am_pktlen;
	__u32			min_pktlen;
	__u32			max_pktlen;
	__u32			rnd_pad;
	__u32			initialized;
	__u32			alpha;
	__u32			beta;
	__u32			delta;
	char			dummy_sent;
	__u8			ident_frag;
	int			tfc_frag_len;
	int			tot_len;
	int 			counter;
	int	 		stima;
	int	 		stima_old;
	int 			trigger_counter;
	int 			flag;
};

In file include/net/xfrm.h there is
struct xfrm_state
{
	//Parameters of TFC 
	int initialized;
	struct timer_list	tfc_alg_timer;
	struct rtable		*dummy_route;
	struct sk_buff_head	tfc_list;
	struct sk_buff_head	dummy_list;
	struct sk_buff_head	tfc_defrag_list;
	__u8			tfc;
	struct tfcparameters	tfc_param;
};

example of using tfc parameters:
// define a xfrm_state and use its variables:
struct xfrm_state *x;
x->tfc_param.fragmentation == 1
*/ 

/// \brief print pointers in skb and the first "size" bytes of the packet. Used in SA_logic()
/// \param *skb is a pointer to the socket buffer (the PDU)
/// \param size is the int first size bytes we want to print
/// \return no return
void skb_print(struct sk_buff *skb, int size)
{
	int i;
	printk(KERN_INFO "TFC skb_print called\n");
	printk(KERN_INFO "data:%p nh:%p h:%p\n ", skb->data, skb->network_header, skb->transport_header);
	printk(KERN_INFO "nh-data:%d h-data:%d\n ", skb->network_header-skb->data, skb->transport_header-skb->data);
        for (i=0; i<size; i++)
	{
                if (skb->network_header+i == skb->transport_header || skb->network_header+i == skb->data) printk(KERN_INFO "\n");
                if (skb->network_header+i == skb->tail) break;
                printk(KERN_INFO "%x ", *(skb->network_header+i));
        }
        printk(KERN_INFO "\n");			
}

/// \brief insert "bytes" size field inside an SKB at absolute position "wherep". Updates skb->{data, h, nh}
/// if needed to point to the same headers. No pointer (only the return value) is set to the new inserted header, 
/// set h or nh explicitly if required!
/// \param *skb is a pointer to the socket buffer (the PDU)
/// \param wherep is a pointer to the absolute position
/// \param bytes is number of bytes to added 
/// \return unsigned char pointer to the start of the inserted part
unsigned char* skb_header_insert(struct sk_buff *skb, unsigned char* wherep, int bytes)
{	
	unsigned char* old_data;// to save the data pointer before push for comodity		
	int bytes_before;	// number of bytes before insert position

	// save the relative position
	bytes_before = wherep - skb->data; 

	// Make sure there is enough space: expand head might change pointers!	
	// Returns zero in the case of success or error, if expansion failed. In the last case, &sk_buff is not changed.
	if (pskb_expand_head(skb,bytes,0,GFP_ATOMIC))
	{
	        printk(KERN_INFO "KCS skb_insert: pskb_expand_head error\n");
	}
	
	// save data pointer
	old_data = skb->data;
	
	// extend buffer with push, this simply substracts "bytes" from "data"
	skb_push(skb,bytes);
	
	// move header to its new place. data is already updated!
	// void *memmove(void *s1, const void *s2, size_t n);
	// The memmove() function operates as efficiently as possible on memory areas. 
	// It does not check for overflow of any receiving memory area. 
	// Specifically, memmove() copies n bytes from memory areas s2 to s1. It returns s1. 
	// If s1 and s2 overlap, all bytes are copied in a preserving manner (unlike memcpy()).
	memmove(skb->data,old_data, bytes_before);

	// update pointers if needed
	if (skb->network_header - old_data < bytes_before ){
                skb->network_header -= bytes;
        }
        if (skb->transport_header  - old_data < bytes_before ){
                skb->transport_header -= bytes;
        }

//	skb->nh.raw = skb->data;
//	skb->h.raw = skb->data + sizeof(struct iphdr);

	return skb->data+bytes_before;
}

// ??? TODO skb->nh.iph->...(look inside)
// ??? TODO skb->nh.iph->...(look inside)
/// \brief TFC fragmentation creates a fragment of size bytes (including the inserted frag header). Used in Packet_transform_len()
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \param size is the size of  padding lenght packed value
/// \return struct sk_buff pointer remainder with frag header
struct sk_buff* tfc_fragment(struct sk_buff *skb, int size)
{
	int fragh_state = 0;
	int preheader_size;
	struct sk_buff *skb_new; // soket packet buffer skb_new initialiazation
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	struct ip_frag_hdr *fragh_new, *fragh = NULL;


	// to be on the safe size, we linearize, since skb seems to be packed in extreme cases (e.g. if padded size goes above MTU)
	skb_linearize(skb);

	// if first fragment
	if(ip_hdr(skb)->protocol != NEXTHDR_FRAGMENT_TFC)
	{
		fragh_state = 1;

		// insert the fragmentation header before the current h; make h point to the new frag header!
		fragh = (struct ip_frag_hdr*) skb_header_insert(skb,skb->transport_header,sizeof(struct ip_frag_hdr));
		skb->transport_header = (void*) fragh;

		// link in fragh in the protocol stack
		fragh->nexthdr = ip_hdr(skb)->protocol;
		ip_hdr(skb)->protocol = NEXTHDR_FRAGMENT_TFC;
	} 
	// if fragh already exists
	else 
	{
		fragh = (struct ip_frag_hdr*)skb->transport_header;
	}
		
	// we have the IP header hanging around, even if we want to do everything relative to the fragmentation header
	preheader_size = skb->transport_header - skb->data;
		
	// allocate skb for remainder and make a copy of the skb (skb_clone doesn't help here)
	skb_new = skb_copy(skb, GFP_ATOMIC);
	fragh_new = (struct ip_frag_hdr*)skb_new->transport_header;

	// prepare the segment by trimming it to the desired size
	// (don't forget the ip header) skb->h points to the frag header, 
	// we need "size" bytes after (including the frag header)
	skb_trim(skb, preheader_size + size);
		
	// prepare the remainder (don't forget the ip header)
	memmove(skb_new->transport_header + sizeof(struct ip_frag_hdr), skb_new->transport_header + size, skb_new->len - (preheader_size + size));
	skb_trim(skb_new, skb_new->len - (size - sizeof(struct ip_frag_hdr)) );
		
	// Riempio i campi header di frammentazione di skb e skb_new
	// Se il pacchetto non e' stato ancora frammentato
	if (fragh_state == 1)
	{  
		if (x->tfc_param.ident_frag == 255) 
		{
			x->tfc_param.ident_frag = 1;
		}
		else 
		{
			x->tfc_param.ident_frag++;
		}			
		fragh->identif = x->tfc_param.ident_frag; // Riempio campo Identif di skb
		fragh_new->identif = x->tfc_param.ident_frag; // Riempio campo Identif di skb_new
		fragh->offset = 0x8000; // Riempio campo M e Offset di skb
		fragh_new->offset = ((size - sizeof(struct ip_frag_hdr)) & 0x7fff); // Riempio campo M e Offset di skb_new
	} 
	// Se il pacchetto e' gia' stato frammentato
	else 
	{
		fragh->offset |= 0x8000; // Riempio campo M e Offset di skb
		fragh_new->offset += size - sizeof(struct ip_frag_hdr); // Riempio campo M e Offset di skb_new
		fragh_new->offset &= (0x7fff);
	} 

	return skb_new;
}

/// \brief Insert TFC header and pre-padding to a pkt. 
/// To avoid kernel panic we expand the skb area of the required amount of space. 
/// This function is called in xfrm4_output.c by xfrm4_encap(), when the space for the ESP header is added: 
/// we also add a TFC header and the additional padding. 
/// KIRALY: why would you do it before queuing? Used in Packet_transform_len()
///
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \param payloadsize is the padding lenght packed value
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
///
/// \return no return

//XFRM_MODE_TRANSPORT says:
/* Add encapsulation header.
 *
 * The IP header will be moved forward to make space for the encapsulation
 * header.
 *
 * On exit, skb->h will be set to the start of the payload to be processed
 * by x->type->output and skb->nh will be set to the top IP header.
 */
 
//XFRM_MODE_TUNNEL says:
/* Add encapsulation header.
 *
 * The top IP header will be constructed per RFC 2401.  The following fields
 * in it shall be filled in by x->type->output:
 *      tot_len
 *      check
 *
 * On exit, skb->h will be set to the start of the payload to be processed
 * by x->type->output and skb->nh will be set to the top IP header.
 */

//nh points to IP header
//h points to next header, i.e. TCP in case of tunnel, FRAG if frag is employed
void tfch_insert(struct sk_buff *skb, int payloadsize,struct xfrm_state *x)
{	
	struct ip_tfc_hdr *tfch;
	WARN_ON(skb->network_header != skb->data);				 
	WARN_ON(skb->transport_header != (void*)(skb->data + sizeof(struct iphdr) + sizeof(struct ip_tfc_hdr)));

	// check if it is header or footer
	if (x->tfc_param.header) 
	{
		//we have specified header_len, so the space for the TFC header was already reserved by the XFRM framework.
		//we don't need to use skb_insert, just find the right place. 
		//For dummies instead, we did not have the placeholder inserted, so we put it here
		//tfch = (void*)skb_header_insert(skb, skb->h.raw , sizeof(struct ip_tfc_hdr));
		tfch = (void*) skb->network_header + ip_hdr(skb)->ihl*4;
		WARN_ON( ((void*)tfch) + sizeof(*tfch) != (void*)skb->transport_header);			
		skb->transport_header = (void*) tfch;
	} 
	else 
	{ 
		// footer
		pskb_expand_head(skb,0,sizeof(struct ip_tfc_hdr),GFP_ATOMIC);
		tfch = (struct ip_tfc_hdr*) skb_put(skb,sizeof(struct ip_tfc_hdr));
	}

	//link in TFC in the protocol "stack"
	if (x->tfc_param.prot_id) 
	{
		//link in TFC in the protocol "stack"
		//nexthdr=protocol originario
		tfch->nexthdr = ip_hdr(skb)->protocol; 
		ip_hdr(skb)->protocol = IPPROTO_TFC;
		if (x->tfc_param.am_pktlen > 1456)
		ip_hdr(skb)->frag_off = 0x0000;
	}
	
	//TODO htons
	tfch->payloadsize = (u_int16_t) payloadsize;
	tfch->spi = x->id.spi;
	ip_hdr(skb)->tot_len = htons(skb->len);
	ip_send_check(ip_hdr(skb));
	return;
}

/// \brief Insert padding in the packet and set all padding byte 0 value. Used in Packet_transform_len()
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \param padsize is the padding lenght packed value
/// \return no return
void padding_insert(struct sk_buff *skb, int padsize)
{
	// pointer to the begin of padding part
	unsigned char * padding_p;
	//printk(KERN_INFO "TFC padding_insert called\n");
	// \brief int pskb_expand_head (struct sk_buff * skb, int nhead, int ntail, int gfp_mask);
	// Check in skb if there is 0 byte between head and data and padsize byte between tail and end. If not make it working.
	// Expands (or creates identical copy, if &nhead and &ntail are zero) header of skb. 
	// &sk_buff itself is not changed. &sk_buff MUST have reference count of 1. 
	// Returns zero in the case of success or error, if expansion failed. In the last case, &sk_buff is not changed.
	pskb_expand_head(skb,0,padsize,GFP_ATOMIC); 
	// A pointer to the first byte of the extra data is returned	
	padding_p = skb_put(skb, padsize);	
	// fill padding with 0
	// void * memset ( void * ptr, int value, size_t num );
	// Sets the first padsize bytes of the block of memory pointed by padding_p to the specified value (interpreted as an unsigned char).
	memset(padding_p, 0, padsize);
	return;	
}

/// calculate the size of the payload: unfortunately the skb already contains the ip header (the pseudo IP header),
/// so we need to subtract its length. It also contains the placeholder for the tfc header, based on header_len
int tfc_get_payload_size(struct sk_buff *skb)
{
	// orig_size = skb->len - skb->nh.iph->ihl*4 - x->props.header_len;
	// previous does not work since the external IP header is not handled the same way in transport and in tunnel
	// in tunnel it is included in header_len, while in transport it isn't. So we calculate it based on h. The following
	// should work for packed (non-linear) skb as well. 
	return skb->len - (skb->transport_header - skb->data);
}

// TODO look for multiplexing possibility. (look inside)
// TODO: handle the case of dummy! (look inside)
/// \brief Receive a packet and change its lenght to pkt_size. Used in SA_logic() function
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \param pkt_size is the requested packet size (only paylaod, without TFC and external IP)
/// \return no return
void packet_transform_len(struct xfrm_state *x, struct sk_buff *skb, int pkt_size) 
{
	struct sk_buff *skb_remainder; // remainder after fragmentation
	int orig_size; // original size of packet (only payload, without TFC and external IP)
	int padding_needed; // calculated size of padding needed
	int tfc_payload_size; // payload_size inside TFC (the rest is padding)

	// calculate the size of the payload
	orig_size = tfc_get_payload_size(skb);

	// the required padding (can be negative) is determined by the requested size, the payload_size and the tfc header size
	padding_needed = pkt_size - orig_size - sizeof(struct ip_tfc_hdr);
	
	// check if padding is allowed and needed	
	if (x->tfc_param.padding && padding_needed > 0) 
	{
		tfc_payload_size = orig_size; // tfc_payload_size remains the original size of the packet
		padding_insert(skb, padding_needed); // Insert padding in the packet
	}
	
	//else if fragmentation allowed && we have a too big packet lenght
	else if ((x->tfc_param.fragmentation == 1) && padding_needed < 0) 
	{
		// the required tfc_payload size is determined by the requested size and the tfc header size
		tfc_payload_size = pkt_size - sizeof(struct ip_tfc_hdr);
		// we set the fragment size (including fragmentation header) to tfc_payload_size
		// struct sk_buff* tfc_fragment(struct sk_buff *skb, int size)
		skb_remainder = tfc_fragment(skb, tfc_payload_size);
		// push back remaining part
		// TODO: handle the case of dummy!
		
		// skb_queue_head - queue a buffer at the list head
		// Queue a buffer at the start of the list. This function takes the
		// list lock and can be used safely with other locking &sk_buff functions safely.
		skb_queue_head(&x->tfc_list,skb_remainder);
	} 
	else 
	{
		tfc_payload_size = orig_size;
	}	

        // add header
        if (x->tfc_param.padding || x->tfc_param.fragmentation || x->tfc_param.multiplexing) 
	{
    		tfch_insert(skb,tfc_payload_size,x);
    	}
}

/// \brief ??? Used in Sa_logic() 
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \return struct sk_buff pointer
struct sk_buff* dequeue(struct xfrm_state *x)
{
	//printk(KERN_INFO "KCS dequeue called\n");
	//select the right queue
	if (!skb_queue_empty(&x->tfc_list)) 
	{
		//if there is a packet in the queue, take it
		//printk(KERN_INFO "KCS dequeue: dequeuing one packet\n");
		x->tfc_param.dummy_sent = 0;
		//printk(KERN_INFO "KCS packet dequeued\n");
		return skb_dequeue(&x->tfc_list);	
	} 
	else if (x->tfc_param.dummy && !skb_queue_empty(&x->dummy_list)) 
	{
		//printk(KERN_INFO "dummy list len = %d\n",skb_queue_len(&x->dummy_list));
		//otherwise take a dummy if dummy packets are enabled
		//TODO: not working for tunnel at the moment
		x->tfc_param.dummy_sent = 1;
		//printk(KERN_INFO "KCS dummy dequeued\n");
		return skb_dequeue(&x->dummy_list);
		//printk(KERN_INFO "MAR send_dummy_pkt -refcnt:%d\n", skb->dst->__refcnt);
	} 
	else 
	{
		//dummy packets are disabled
		x->tfc_param.dummy_sent = 0;
		//printk(KERN_INFO "KCS nothing dequeued\n");
		return NULL;
	}
}

/// \brief builds and queues dummy pkts (max 15) in dummy_list, using the dummy route of the SA to route the pkt. Used in SA_logic()
///	   pointers are set according to the mode, see comments for tfch_insert() for more info.
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \return no return
void build_dummy_pkt(struct xfrm_state *x)
{
	int i; // used in ciclo for
	int len = 500;
	int header_len = MAX_HEADER;		
	struct sk_buff *skb; // soket packet buffer initialiazation
	struct iphdr *iph; // ip header initialiazation

	// check if buffer have less then 15 dummy packet
	if (skb_queue_len(&x->dummy_list)<150)
	{
		// it generates till 15 dummy packet
		for (i = 0; i < (150 - skb_queue_len(&x->dummy_list)); i++)
		{
			// allocate a new skb for dummy pkt with lenght len
			if ((skb = alloc_skb(len, GFP_ATOMIC)) == NULL) 
			{
				// ALLERT no memory
				NETDEBUG(KERN_INFO "build_dummy_pkt - no memory for new dummy!\n");
				return;
			}
			// void skb_reserve (struct sk_buff* skb, unsiged int len) 
			// Increase the headroom of an empty &sk_buff by reducing the tail room. This is only allowed for an empty buffer
			skb_reserve(skb, header_len);
			// unsigned char * skb_put (struck sk_buff * skb, unsigned int len)
			// This function extends the used data aerea of the buffer. 
			// If this would exceed the total buffer size the kernel will panic.
			// A pointer to the first byte of the extra data is returned
			skb_put(skb,100);
			// set skb->h to point to the beginning of the buffer
			skb->network_header = skb->data;
			//add the space for the IP header and TFC header. We add the space for the TFC header as well
			//to generate similar packages that would arrive from the XFRM framework.
			switch (x->props.mode) {
			    case XFRM_MODE_TRANSPORT:
				skb->transport_header = (void*)(skb->data + sizeof(struct iphdr) + x->props.header_len);
				break;
			    case XFRM_MODE_TUNNEL:
				// in tunnel mode the size of the ip header is already part of header_len
				skb->transport_header= (void*)(skb->data + x->props.header_len);
				break;
			    default:
				NETDEBUG(KERN_INFO "unnknown XFRM MODE, guessing dummy format!\n");
				skb->transport_header = (void*)(skb->data + x->props.header_len);
			}
			//fill the IP header
			iph = ip_hdr(skb);
			iph->version = 4;
			iph->ihl = 5;
			iph->tos = 0;
			iph->tot_len = htons(skb->len);
			iph->frag_off = 0;
			iph->id = 0;
			iph->ttl = 200; 
			iph->protocol = IPPROTO_DUMMY; // IPPROTO_dummy in this case
			iph->saddr = x->dummy_route->rt_src; 
			iph->daddr = x->dummy_route->rt_dst; // daddr: less important byte first
			ip_hdr(skb)->tot_len = htons(skb->len);
			skb->dst = &x->dummy_route->u.dst;
			dst_hold(skb->dst); // indica che c'e' un pacchetto che sta usando quella dst
			
			if(skb->dst != NULL)
			{
				//come dst utilizziamo quella costruita durante _xfrm_state_insert
				// void skb_queue_tail (struct sk_buff_head *list, struct sk_buff *newsk)
				// Queue a buffer at the tail of the list. This function takes the list lock and can be used
				// safely with other locking &sk_buff functions safely.
				// a buffer cannot be placed on two lists at the same time
				skb_queue_tail(&x->dummy_list,skb);
				return;
			}
			else 
			{
				// void kfree_skb (struct sk_buff *skb)
				// Drop a reference to the buffer and free it if the usage count has hit zero
				kfree_skb(skb);
				return;
			}
		}
	}
}

//TODO: check is tunnel or transport. (look inside)
/// \brief costruisco una struttura flowi in cui inserisco l'indirizzo sorgente e destinazione della SA, con cui andiamo a creare la catena di dst_entry e la salviamo in x->dummy_route. Used in SA_logic() 
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \return int err 
int create_dummy_route(struct xfrm_state *x)
{
	int err; // error local variable
    
	//fabrizio - creo la rtable per questa SA..mi serve per poter instradare i pacchetti dummy
	struct flowi fl = { .oif = 0,
			    .nl_u = { .ip4_u =
				      { .daddr = x->tfc_param.daddr_dummy /*x->id.daddr.a4*/,
					.saddr = x->tfc_param.saddr_dummy/*x->props.saddr.a4*/,
					.tos = 0} },
			    .proto = IPPROTO_TFC,
			    //.proto = 0,
	};

	err = ip_route_output_key(&x->dummy_route, &fl);
	if (err) 
	{
		printk(KERN_INFO "FAB dummy_init - ip_route_output_key failed! err = %d\n",err);
		//cskiraly: set this to null to signal that other structures doesn't have to be destroyed at the end 
		x->dummy_route = NULL;
		return err;
	};
	// increase reference count on dst structure
	dst_hold(&x->dummy_route->u.dst);
	return 0;
}

/// \brief Main function. Receive a xfrm entity (SA) and trasforme the packet in the way x->tfc.param required
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \return no return
void SA_Logic(struct xfrm_state *x)
{
	struct sk_buff *skb = NULL;
	unsigned long	rand1;
	int modulo = 3;
	int pktlen;
	int padlen;
	unsigned long delay = 0;
	int i;
	int a = 0;
	int err; // error local variable

	if (x->tfc_param.dummy) // TFC DUMMY PACKET ON
	{
		if (!x->dummy_route || x->tfc_param.dummy_sent) // ???
		{
			if ((err = create_dummy_route(x))!=0) // failed
			{
				printk(KERN_INFO "KCS can't create dummy route, suppose it is an incoming SA\n");
				return; // returning without renewing the timer, It won't be called for this SA anymore
			}
			else
			{
				// generation of new dummy packet with x is a xfrm state (SA) 
				build_dummy_pkt(x);
			}
			
		}
	}
	
	// allow to manage tfc_param.batch_size packet in the same way (ITA batch=gruppo)
 	for (i=0; i<x->tfc_param.batch_size; i++) 
 	{
 		//dequeue a packet, or a dummy, or nothing (NULL)
		skb = dequeue(x);

		// check if in soket buffer is present a packet 
		if (skb) 
		{
			// Size algorithm is applayed
			switch (x->tfc_param.size_algorithm)
			{
				//nothing
				case 0:
				// Constant Packet Lenght Rate
				case 1:	pktlen = x->tfc_param.am_pktlen;
					packet_transform_len(x, skb, pktlen);
					break;
				// Random lenght packet between a min_pktlen and a max pktlen values (uniform distribution)
				// If lenght is more than max_pktleng packet will lost (????)
				case 2:	get_random_bytes(&rand1,4);
					pktlen = x->tfc_param.min_pktlen + rand1%(x->tfc_param.max_pktlen-x->tfc_param.min_pktlen+1);
					packet_transform_len(x, skb, pktlen);
					break;
				// Random padding: lenght of the padding (not as in case 2 of packet)
				// is between [0 - rnd_pad value] (uniform distribution)
				case 3:	get_random_bytes(&rand1,4);
					padlen = rand1%(x->tfc_param.rnd_pad+1);
					pktlen = tfc_get_payload_size(skb) + padlen; 
					packet_transform_len(x, skb, pktlen);
					break;
				// default case, nothing is done
				default: printk(KERN_INFO "FRA SA_Logic: size alg case default\n");
					 break;
			}
			
			//we are the current destination, so we shuold pop the next one in the dst stack
			if (!(skb->dst = dst_pop(skb->dst))) {
			    printk(KERN_INFO "KCS SA_Logic: dst_pop error while sending packet\n");
			}
			
			//pass on the skb to the next layer
			dst_output(skb);
		}
 	}
	// build dummies after sending the whole batch (FMA moved out for cycle
	if (x->tfc_param.dummy_sent) 
	{
		build_dummy_pkt(x);
	}
	//Calcolo il # di pkt che devo inviare con l'algoritmo relativo alla SA
	switch (x->tfc_param.delay_algorithm)
	{
		case 0:	
		case 1:	//CBR
			delay = HZ / x->tfc_param.sa_hz;
			break;
		case 2:	//random IPD (inter-packet-delay)
			//grometric in [0 ... 1/sa_hz sec]
			get_random_bytes(&rand1,4);
			delay = HZ / x->tfc_param.sa_hz / (1 + (rand1%modulo));
			break;
		case 3: //???
			delay = HZ / (1 + (a%modulo));
			a++;
			if(a>=modulo) a = 0;
			break;
	}
	// ???
	del_timer(&x->tfc_alg_timer);
	x->tfc_alg_timer.expires +=  delay;
	add_timer(&x->tfc_alg_timer);
}

/// \brief ??? Used in tfc_handler.c: function tfc_input()
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \return unsigned int
unsigned int tfc_remove(struct sk_buff *skb, struct xfrm_state *x)
{
	int tfc_payloadsize;
        struct ip_tfc_hdr *tfch;
	//struct iphdr *iph;

	// linearize and restore pointers
	skb_linearize(skb);
	//tfch = (struct ip_tfc_hdr*) (skb->nh.raw + (skb->nh.iph->ihl*4)); //TODO why not using skb->h???
	tfch = (struct ip_tfc_hdr*) skb->transport_header;

	//set next protocol in IP to the one after TFC
	ip_hdr(skb)->protocol = tfch->nexthdr;
	
	//remove TFC header
	tfc_payloadsize = tfch->payloadsize;
	memmove(skb->transport_header, skb->transport_header + sizeof(struct ip_tfc_hdr), tfc_payloadsize);

	//remove padding
	//It is better to do "trim" calculated from "tfc_payloadsize"
	//so it works indifferent of whether data points to the IP header or the TFC heaer
	skb_trim(skb, tfc_payloadsize + (skb->transport_header - skb->data));
	ip_hdr(skb)->tot_len = htons(skb->len + ((void*)skb->data - (void*)skb->network_header));
	return NF_ACCEPT;
}

/// \brief Assemble fragments.
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \return no return	
static void tfc_defrag2(struct sk_buff *skb, struct xfrm_state *x) 
{
	int datalen;
	struct sk_buff *skb_frag;
	struct ip_frag_hdr *fragh, *fragh_new;
	struct iphdr *iph_new;

	datalen = skb->len + ((void*)skb->data - (void*)skb->network_header);
	//pskb_expand_head invalidates ponters! We do that first.
	if (pskb_expand_head(skb, 0, x->tfc_param.tfc_frag_len - sizeof(struct ip_frag_hdr), GFP_ATOMIC))
	{
		printk(KERN_INFO "KCS error in pskb_expand_head!\n");
		return;
	}

	//adjust the protocol field in the IP header
	iph_new = ip_hdr(skb);
	//fragh = skb->nh.raw + iph_new->ihl*4;
	fragh = (void*) skb->transport_header;
	iph_new->protocol = fragh->nexthdr;
	
	//add space for all the fragments
	skb_put(skb, x->tfc_param.tfc_frag_len - sizeof(struct ip_frag_hdr));

	//move the last segment to its place (not counting for a frag header)
	memmove(skb->data + iph_new->ihl*4 + ((fragh->offset) & 0x7fff), skb->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), datalen - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
	
	//printk(KERN_INFO "EMA prima del while \n");
	while (!skb_queue_empty(&x->tfc_defrag_list))
	{
		skb_frag = skb_dequeue(&x->tfc_defrag_list);
		fragh_new = (struct ip_frag_hdr*)(skb_frag->network_header + iph_new->ihl*4);
		if((fragh_new->offset & 0x8000) == 0x8000)
		{
			memmove(skb->data + iph_new->ihl*4 + (fragh_new->offset & 0x7fff), skb_frag->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->network_header) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
		}
		else 
		{
			pskb_expand_head(skb, 0, skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->network_header) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr), GFP_ATOMIC);
			skb_put(skb, skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->network_header) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
			memmove(skb->data + iph_new->ihl*4 + (fragh_new->offset & 0x7fff), skb_frag->data + iph_new->ihl*4 + sizeof(struct ip_frag_hdr), skb_frag->len + ((void*)skb_frag->data - (void*)skb_frag->network_header) - iph_new->ihl*4 - sizeof(struct ip_frag_hdr));
		}
	}
	//printk(KERN_INFO "EMA defragment accomplishied. OLE \n");
	skb->transport_header = (void*)fragh;
	//ip_send_check(iph_new);
	ip_hdr(skb)->tot_len = htons(skb->len + ((void*)skb->data - (void*)skb->network_header));
	ip_send_check(iph_new);
	return;
}

/// \brief Remove fragmentation header, and put fragment in queue. If all frgments are available, 
/// call defrag2 to reassemble the packet.
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \return unsigned int NF_STOLEN 
unsigned int tfc_defrag(struct sk_buff *skb, struct xfrm_state *x)
{
	struct ip_frag_hdr *fragh;
	struct iphdr *iph;
	struct sk_buff * skb2;

	iph = ip_hdr(skb);
	fragh = (void*) skb->transport_header;
	if ((fragh->offset & 0x8000) == 0x8000)
	{ 	
		//Se M = 1 printk(KERN_INFO "EMA no last fragment\n");
		x->tfc_param.tfc_frag_len += skb->len + ((void*)skb->data - (void*)skb->network_header) - iph->ihl*4 - sizeof(struct ip_frag_hdr);
	} 
	else 
	{
		//printk(KERN_INFO "EMA last fragment\n");
		x->tfc_param.tot_len += fragh->offset;
	}		
	if(x->tfc_param.tfc_frag_len == x->tfc_param.tot_len) 
	{
		//printk(KERN_INFO "EMA total fragment\n");
		//return NF_STOLEN;
		tfc_defrag2(skb,x);
		x->tfc_param.tfc_frag_len = 0;
		x->tfc_param.tot_len = 0;
		//printk(KERN_INFO "EMA defragment\n");
		return NF_ACCEPT;
	}
	
	//try to clone it, since it will be deleted after we give back an error
	skb2 = skb_clone(skb,GFP_ATOMIC);
	skb_queue_tail(&x->tfc_defrag_list, skb2);
	//printk(KERN_INFO "EMA stolen\n");
	return NF_STOLEN;
}

/// \brief ??? Used in tfc_apply() 
/// \param int ???????????? 
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \return no return 
void len_est(int rec_pkt_l,struct xfrm_state *x)
{
	int diff;
	//printk(KERN_INFO "TFC len_est called\n");
	//printk(KERN_INFO"pkt_len: %d\n",rec_pkt_l);
	if (x->tfc_param.stima_old == 0) x->tfc_param.stima_old = rec_pkt_l;
	x->tfc_param.stima = x->tfc_param.stima_old + (rec_pkt_l >> x->tfc_param.alpha) - (x->tfc_param.stima_old >> x->tfc_param.alpha);
	//printk(KERN_INFO"stimatore: %d\n",x->tfc_param.stima);
	if (x->tfc_param.counter < x->tfc_param.beta ) 
	{	
		x->tfc_param.counter=(x->tfc_param.counter+1);
	}
	else 
	{
		//printk(KERN_INFO "valore stimato: %d\n",x->tfc_param.stima);
		diff = rec_pkt_l-x->tfc_param.stima_old;  //differenza tra valore reale e quello atteso
		if (diff <0) diff = -diff;
		if (diff < x->tfc_param.delta) 
		{
			if (x->tfc_param.trigger_counter < 5 && rec_pkt_l > 1000) 
			{	
				x->tfc_param.trigger_counter +=1;
			}
			else 
			{
				if (x->tfc_param.trigger_counter == 5)
				{
					if (x->tfc_param.flag == 0)
					{
						//printk(KERN_INFO "MODIFICO PARAMETRI\n");
						x->tfc_param.am_pktlen = 800;
						x->tfc_param.flag = 1;
					} 
					else 
					{
						//printk(KERN_INFO "NON RIMODIFICO PARAMETRI\n");
					}
				}
			}
		}
		else 
		{
			if(x->tfc_param.flag == 1)
			{
				//printk(KERN_INFO "RITORNO COME PRIMA\n");
				x->tfc_param.am_pktlen = 1300;
			}
			x->tfc_param.flag = 0;
			x->tfc_param.trigger_counter = 0;
			//printk(KERN_INFO "non faccio nulla\n");
		}
		x->tfc_param.stima_old= x->tfc_param.stima;
		return;
	}
}

/// \brief ??? Used in tfc_handler.c: function tfc_output()  
/// \param xfrm_state is a pointer to a xfrm entity (SA) with TFC values too
/// \param sk_buff is a pointer to the socket buffer (the PDU)
/// \return unsigned int NF_STOLEN

// called from xfrm4_output_one
// it first calls the putput function of the "mode", then the output of "type", i.e. this
unsigned int tfc_apply(struct xfrm_state *x,struct sk_buff *skb)
{
	//printk(KERN_INFO "TFC tfc_apply called\n");
	//deleted in if: || skb->nh.iph->protocol == IPPROTO_TFC*/
	if((x->tfc_param.max_queue_len != 0 && skb_queue_len(&x->tfc_list) >= x->tfc_param.max_queue_len))
	{
		printk(KERN_INFO "KCS tfc_apply: queue full\n");
		return NF_DROP;
	}
	else
	{
		int rec_pkt_l = skb->len;
		// printk(KERN_INFO"lunghezza pacchetto: %d\n",rec_pkt_l);
		len_est(rec_pkt_l,x);
		// skb_queue_tail(&x->tfc_list,skb_cp);
		skb_queue_tail(&x->tfc_list,skb);
		return NF_STOLEN;
	}
}

EXPORT_SYMBOL(build_dummy_pkt);
EXPORT_SYMBOL(SA_Logic);
EXPORT_SYMBOL(tfc_apply);
EXPORT_SYMBOL(tfc_remove);
EXPORT_SYMBOL(tfc_defrag);
//EXPORT_SYMBOL(tfch_insert);
EXPORT_SYMBOL(dequeue);
EXPORT_SYMBOL(skb_print);
EXPORT_SYMBOL(packet_transform_len);

static int __init init(void)
{
	return 0;
}

static void __exit fini(void)
{
}

module_init(init);
module_exit(fini);
