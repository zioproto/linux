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
