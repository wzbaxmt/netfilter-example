#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("caydyn <caydyn@icloud.com>");
MODULE_DESCRIPTION("netfilter hook");

enum { 
    NF_IP_PRE_ROUTING, 	//在完整性校验之后，选路确定之前
	NF_IP_LOCAL_IN,		//在选路确定之后，且数据包的目的是本地主机
	NF_IP_FORWARD,		//目的地是其它主机地数据包
	NF_IP_LOCAL_OUT,	//来自本机进程的数据包在其离开本地主机的过程中
	NF_IP_POST_ROUTING,	//在数据包离开本地主机“上线”之前
	NF_IP_NUMHOOKS
};
#if 0
而netfilter的返回值有5种：
返回值                含义
NF_DROP				丢弃该数据包
NF_ACCEPT			保留该数据包
NF_STOLEN			忘掉该数据包
NF_QUEUE			将该数据包插入到用户空间
NF_REPEAT			再次调用该hook函数
#endif
static struct nf_hook_ops nfho;
struct sk_buff *sock_buff;

unsigned int
hookfn(const struct nf_hook_ops *ops, struct sk_buff *skb,
       const struct net_device *in, const struct net_device *out,
       int (*okfn) (struct sk_buff *))
{
    uint8_t proto;
    struct ethhdr *eth;
	struct iphdr *ipv4h;
    struct ipv6hdr *ipv6h;

    char message[128] = { 0 };
	unsigned char h_dest[6] = { 0 };
	unsigned char h_source[6] = { 0 };

	if (!skb)
		return NF_ACCEPT;

    memset(message, 0, 128);
	memset(h_dest, 0, 6);
	memset(h_source, 0, 6);

    eth = (struct ethhdr *)skb_mac_header(skb);
	//		h_dest = eth->h_dest;
	//		h_source = eth->h_source;
	int i = 0;
	printk(KERN_INFO "h_source is");
	for(i = 0; i < 6; i++)
{
	printk(KERN_INFO "%x ", eth->h_source[i]);
}
	printk(KERN_INFO " \n");
	printk(KERN_INFO "h_dest is");
	for(i = 0; i < 6; i++)
{
	printk(KERN_INFO "%x ", eth->h_dest[i]);
}
	printk(KERN_INFO " \n");
    switch(ntohs(eth->h_proto))
    {
        case ETH_P_IP:
            {
                strcpy(message, "got ipv4 ");
	            ipv4h = (struct iphdr *) skb_network_header(skb);
                proto = ipv4h->protocol;
            }
            break;
        case ETH_P_IPV6:
            {
                strcpy(message, "got ipv6 ");
	            ipv6h = (struct ipv6hdr *) skb_network_header(skb);
                proto = ipv6h->nexthdr;
            }
            break;
        default:
            printk(KERN_INFO "l3 protocol: %X\n", eth->h_proto);
    }

    switch(proto)
    {
        case IPPROTO_TCP:
            strcat(message, "tcp packet");
            break;
        case IPPROTO_UDP:
            strcat(message, "udp packet");
            break;
        case IPPROTO_ICMP:
            strcat(message, "icmp packet");
			//break;
			printk(KERN_INFO "ICMP drop %s\n", message);
			return NF_DROP;
    }

    printk(KERN_INFO "%s\n", message);
	
	//return NF_DROP;

	return NF_ACCEPT;
}

#if 0
struct nf_hook_ops
{
        struct list_head list;                        //链表成员,链表头，用来把各个处理函数组织成一个表，初始化为{NULL，NULL}；
        /* User fills in from here down. */
        nf_hookfn *hook;                        //钩子函数指针,我们定义的处理函数的指针，它的返回值必须为前面所说的几个常量之一
        struct module *owner;
        int pf;                                        //协议簇,表示这个HOOK属于哪个协议族对于ipv4而言，是PF_INET
        int hooknum;                                //hook类型,取值为五个钩子之一
        /* Hooks are ordered in ascending priority. */
        int priority;                                //优先级,目前Netfilter定义了一下几个优先级，取值也小优先级也高
};
支持的协议类型
	enum {
    63		NFPROTO_UNSPEC =  0,
    64		NFPROTO_IPV4   =  2,
    65		NFPROTO_ARP    =  3,
    66		NFPROTO_BRIDGE =  7,
    67		NFPROTO_IPV6   = 10,
    68		NFPROTO_DECNET = 12,
    69		NFPROTO_NUMPROTO,
    70	};

#endif
static int __init hook_init(void)
{
	nfho.hook = hookfn;
	nfho.hooknum = NF_IP_LOCAL_IN;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho);

	return 0;
}

static void __exit hook_exit(void)
{
	nf_unregister_hook(&nfho);
}

module_init(hook_init);
module_exit(hook_exit);
