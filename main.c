#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Mr.Wang <wzbaxmt@gmail.com>");
MODULE_DESCRIPTION("netfilter             example");

static struct nf_hook_ops nfho;
struct sk_buff *sock_buff;

unsigned int hookfn(const struct nf_hook_ops *ops, struct sk_buff *skb,
       const struct net_device *in, const struct net_device *out,
       int (*okfn) (struct sk_buff *))
{
    uint8_t proto;
    struct ethhdr *eth;
	struct iphdr *ipv4h;
    struct ipv6hdr *ipv6h;
	struct tcphdr	*tcph = NULL;//tcp头部
	struct udphdr	*udph = NULL;//tcp头部
	
    char message[128] = { 0 };
	if (!skb)
		return NF_ACCEPT;

    memset(message, 0, 128);
	printk("*********************************************************************\n");
    eth = (struct ethhdr *)skb_mac_header(skb);
	printk("h_dest:%pM, h_source:%pM, h_proto:%x\n",eth->h_dest, eth->h_source, ntohs(eth->h_proto));
    switch(ntohs(eth->h_proto))
    {
        case ETH_P_IP:
        {
        	strcpy(message, "got ipv4 ");
	    	ipv4h = (struct iphdr *) skb_network_header(skb);
			printk("version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",\
			ipv4h->version,ipv4h->ihl,ipv4h->tos,ntohs(ipv4h->tot_len),ntohs(ipv4h->id), ntohs(ipv4h->frag_off) & ~(0x7 << 13),ipv4h->ttl,ipv4h->protocol,ipv4h->check,&ipv4h->saddr,&ipv4h->daddr);
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
        {
			tcph = (struct tcphdr *) ((u8 *) ipv4h + (ipv4h->ihl << 2)); //important!
			printk("source:%d, dest:%d, seq:%d, ack_seq:%d, res1:%d,doff:%d, fin:%d, syn:%d, rst:%d, psh:%d, ack:%d, urg:%d, ece:%d,cwr:%d, window:%d, check:%d, urg_ptr:%d\n",\
				ntohs(tcph->source),ntohs(tcph->dest),ntohs(tcph->seq),ntohs(tcph->ack_seq),tcph->res1,tcph->doff,tcph->fin,tcph->syn,tcph->rst,tcph->psh,tcph->ack,tcph->urg,
				tcph->ece,tcph->cwr,ntohs(tcph->window),tcph->check,ntohs(tcph->urg_ptr));
        	strcat(message, "tcp packet");
            break;
        }
        case IPPROTO_UDP:
        {
			udph = (struct udphdr *) ((u8 *) ipv4h + (ipv4h->ihl << 2)); //important!	
			printk("UDP!! source:%d, dest:%d, len:%d\n",ntohs(udph->source),ntohs(udph->dest),ntohs(udph->len));
            strcat(message, "udp packet");
            break;
        }
        case IPPROTO_ICMP:
            strcat(message, "icmp packet");
			printk(KERN_INFO "ICMP drop %s\n", message);
			return NF_DROP;
    }

    printk(KERN_INFO "%s\n", message);
	
	return NF_ACCEPT;
}
	   
static int __init hook_init(void)
{
	nfho.hook = hookfn;
	nfho.hooknum = NF_INET_LOCAL_IN;
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
