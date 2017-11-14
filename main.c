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
    NF_IP_PRE_ROUTING, 	//��������У��֮��ѡ·ȷ��֮ǰ
	NF_IP_LOCAL_IN,		//��ѡ·ȷ��֮�������ݰ���Ŀ���Ǳ�������
	NF_IP_FORWARD,		//Ŀ�ĵ����������������ݰ�
	NF_IP_LOCAL_OUT,	//���Ա������̵����ݰ������뿪���������Ĺ�����
	NF_IP_POST_ROUTING,	//�����ݰ��뿪�������������ߡ�֮ǰ
	NF_IP_NUMHOOKS
};
#if 0
��netfilter�ķ���ֵ��5�֣�
����ֵ                ����
NF_DROP				���������ݰ�
NF_ACCEPT			���������ݰ�
NF_STOLEN			���������ݰ�
NF_QUEUE			�������ݰ����뵽�û��ռ�
NF_REPEAT			�ٴε��ø�hook����
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
        struct list_head list;                        //�����Ա,����ͷ�������Ѹ�����������֯��һ������ʼ��Ϊ{NULL��NULL}��
        /* User fills in from here down. */
        nf_hookfn *hook;                        //���Ӻ���ָ��,���Ƕ���Ĵ�������ָ�룬���ķ���ֵ����Ϊǰ����˵�ļ�������֮һ
        struct module *owner;
        int pf;                                        //Э���,��ʾ���HOOK�����ĸ�Э�������ipv4���ԣ���PF_INET
        int hooknum;                                //hook����,ȡֵΪ�������֮һ
        /* Hooks are ordered in ascending priority. */
        int priority;                                //���ȼ�,ĿǰNetfilter������һ�¼������ȼ���ȡֵҲС���ȼ�Ҳ��
};
֧�ֵ�Э������
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
