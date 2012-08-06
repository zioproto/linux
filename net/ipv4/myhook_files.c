#include <net/my_tfc.h>

int build_padding(struct sk_buff *skb)
{	int mode = 0;
	int padsize;
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	if(mode==2) x->max_pkt_size[0] = 1400;
	padsize = x->max_pkt_size[x->s] - skb->len;
	printk(KERN_INFO "MAR padding - padsize: %d\n", padsize);
	
	if(mode==1){ // Andameto del padding a dente di sega
		x->max_pkt_size[0] += 10;
		if(x->max_pkt_size[0] > 1400) x->max_pkt_size[0] = 0;
		printk(KERN_INFO "MAR padding - next-max_pkt_size: %d\n", x->max_pkt_size);
		return padsize;
	}
	// Andamento del padding tipo seno
	switch (x->s){
		case 0: //x->max_pkt_size = 700;
			x->s = 1;
			break;
		case 1: //x->max_pkt_size = 1212;
			x->s = 2;
			break;
		case 2: //x->max_pkt_size = 1400;
			x->s = 3;
			break;
		case 3: //x->max_pkt_size = 1212;
			x->s = 4;
			break;
		case 4: //x->max_pkt_size = 700;
			x->s = 5;
			break;
		case 5: //x->max_pkt_size = 0;
			x->s = 0;
			break;
		
	}
	printk(KERN_INFO "MAR padding - next-max_pkt_size: %d\n", x->max_pkt_size[x->s]);
	
	/*x->max_pkt_size += x->s * 10;
	if(x->max_pkt_size > 1400) x->s = -1;
	if(x->max_pkt_size == 0) x->s = 1;*/
	return padsize;
}

void padding_insert(struct sk_buff *skb)
{
	struct ip_tfc_hdr *tfch;
	struct iphdr *iph;
	int padsize;
	padsize = build_padding(skb);
	if(padsize<0) padsize=0;
	//iph = skb->nh.iph;
	printk(KERN_INFO "MAR Tailroom: %d,\n",skb_tailroom (skb));
	pskb_expand_head(skb,0,padsize,GFP_ATOMIC);
	printk(KERN_INFO "MAR Tailroom: %d,\n",skb_tailroom (skb));
	tfch = skb->nh.raw + (iph->ihl*4);
	tfch->padsize = padsize;
	skb_put(skb, tfch->padsize);
	printk(KERN_INFO "MAR padding_insert - padlen: %d,\n", padsize);
	return;
	
}


/**
Receiving side, remove TFC header and padding
*/
void tfc_remove(struct sk_buff *skb)
{	u8 workbuf[60];
	//u8 *p;
        //unsigned int i = 0;
        struct ip_tfc_hdr *tfch;
	struct iphdr *iph;
	iph = skb->nh.iph;
	tfch = skb->nh.raw + (iph->ihl*4);
	printk(KERN_INFO "RICEVUTO PACCHETTO TFC -len:%2d, skb->nh.raw:%x, tfch:%x\n",\
		skb->len, skb->nh.raw, tfch);
	skb->nh.iph->protocol = tfch->nexthdr;
	pskb_trim(skb, skb->len - tfch->padsize);
	memcpy(workbuf, skb->nh.raw, iph->ihl*4);

        /*while(i < 20){
		printk(KERN_INFO "%x ",*(workbuf + i));
		i++;
                }
	printk(KERN_INFO "\nRICEVUTO PACCHETTO TFC,dopo trim -len:%d,iph->protocol:%x,\
		skb->nh.raw:%x, tfch:%x\n",\
		skb->len,skb->nh.iph->protocol, skb->nh.raw, tfch);
	*/
	skb->h.raw = skb_pull(skb, sizeof(struct ip_tfc_hdr));
	skb->nh.raw += sizeof(struct ip_tfc_hdr);
	memcpy(skb->nh.raw, workbuf, iph->ihl*4);
	/*printk(KERN_INFO "RICEVUTO PACCHETTO TFC,dopo pull - len:%d, skb->nh.raw:%x,\
			skb->h.raw:%x, protocol:%x\n",\
                        skb->len, skb->nh.raw, skb->h.raw, skb->nh.iph->protocol);
	*/
	skb->nh.iph->tot_len = htons(skb->len);
	return;
}


EXPORT_SYMBOL(tfc_remove);
EXPORT_SYMBOL(build_padding);
EXPORT_SYMBOL(padding_insert);
