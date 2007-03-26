#define TFC_ATTACH_PROTO IPPROTO_AH
#define NEXTHDR_FRAGMENT_TFC 254

void EspTfc_SA_init(struct xfrm_state *x);


struct sk_buff* tfc_input(struct sk_buff *skb);
unsigned int tfc_defrag1(struct sk_buff *sb);
