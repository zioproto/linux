/**
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version
 2 of the License, or (at your option) any later version.

 \file $Id$
 \author Fabrizio Formisano, Csaba Kiraly, Emanuele Delzeri, Simone Teofili, Francesco Mantovani
*/

#define TFC_ATTACH_PROTO IPPROTO_AH
#define NEXTHDR_FRAGMENT_TFC 254

//fill the queue of dummy packets
void build_dummy_pkt(struct xfrm_state *x);
//add TFC header
unsigned int tfc_apply(struct xfrm_state *x,struct sk_buff *skb);
//start the logic (per SA)
void SA_Logic(struct xfrm_state *x);
void prova_logic(struct xfrm_state *x);
//remove TFC header
unsigned int tfc_remove(struct sk_buff *skb, struct xfrm_state *x);
//remove FAG header
unsigned int tfc_defrag(struct sk_buff *skb, struct xfrm_state *x);

int tfc_dst_stolen(struct sk_buff *skb);

void tfch_insert(struct sk_buff *skb, int payloadsize, struct xfrm_state *x);
