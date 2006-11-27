#include <linux/compiler.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netfilter_ipv4.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/pfkeyv2.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

#include <asm/scatterlist.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/esp.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/snmp.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/inetpeer.h>
#include <net/checksum.h>

#define TFC_ATTACH_PROTO IPPROTO_AH

//void tfch_insert(struct sk_buff *skb, int padsize);
//struct sk_buff* tfc_fragment(struct sk_buff *skb, int size);
//void tfc_SA_remove(struct xfrm_state *x);
//void send_pkt(unsigned long data);


//extern struct timer_list	TFC_control;
