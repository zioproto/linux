#define TFC_ATTACH_PROTO IPPROTO_AH
#define NEXTHDR_FRAGMENT_TFC 254

//fill the queue of dummy packets
void build_dummy_pkt(struct xfrm_state *x);
//add TFC header
unsigned int tfc_apply(struct xfrm_state *x,struct sk_buff *skb);
//start the logic (per SA)
void SA_Logic(struct xfrm_state *x);

//remove TFC header
unsigned int tfc_remove(struct sk_buff *skb);
//remove FAG header
unsigned int tfc_defrag(struct sk_buff *skb);

// struct tfcparameters {
// // 	struct timer_list	*tfc_alg_timer;
// // 	struct rtable		*dummy_route;
// // 	struct sk_buff_head	*tfc_list;
// // 	struct sk_buff_head	*dummy_list;
// 	__u8			delay_algorithm;
// 	__u32			saddr_dummy;
// 	__u32			daddr_dummy;
// 	int 			tfc;
// 	int 			header;
// 	int			prot_id;
// 	int			dummy;
// 	int 			padding;
// 	int			fragmentation;
// 	int			multiplexing;
// 	int			sa_hz;
// 	int			max_queue_len;
// 	int			batch_size;
// 	int			picco;
// 	int			size_algorithm;
// 	int			am_pktlen;
// 	int			min_pktlen;
// 	int			max_pktlen;
// 	int			rnd_pad;
// };
