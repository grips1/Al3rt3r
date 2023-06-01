#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/time.h>
#include <linux/timekeeping.h>

#define XMAS_SCAN_THRESH 200
#define NULL_SCAN_THRESH 200
#define FIN_SCAN_THRESH 200
#define SYN_SCAN_THRESH 200
#define SCAN_TIMEOUT 5

MODULE_LICENSE("GPL");
MODULE_AUTHOR("grips1");
MODULE_DESCRIPTION("Nmap-specific IPS");

static struct nf_hook_ops nfho;


typedef struct packet_history
{
	u32 src_addr;
	ktime_t timestamp; 	
	u16 counter;
} p_history;

p_history syn_history,
		  fin_history,
		  xmas_history,
		  null_history;

void prints(u32 address)
{
    struct in_addr addr;
    addr.s_addr = htonl(address);
    printk(KERN_WARNING "Deteced scan from source address:%pI4\n", &addr);
}

void setparams(struct iphdr, ktime_t current_time, struct* p_history)  
{
	p_histroy->src_addr = iphdr->saddr;
	p_history->timestamp = current_time;
	p_history->counter = 0;
}

static unsigned int detection_logic(void* priv,
									struct sk_buff* sk_buff,
									const struct nf_hook_state* state)
{
	struct iphdr* iph;
	struct tcphdr* tcph;
	u32 s_addr;
	ktime_t current_packet_time;
	s64 time_diff_nano, time_diff_sec;
	current_packet_time = ktime_get_real();
	if(!sk_buff) return NF_ACCEPT;
	iph = ip_hdr(sk_buff);
	if(iph->protocol != IPPROTO_TCP) return NF_ACCEPT;
	tcph = tcp_hdr(sk_buff);
	s_addr = ntohl(iph->saddr);

	if(tcph->syn && !(tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin) && syn_history.src_addr == s_addr)//SYN scan
	{
		time_diff_nano = ktime_to_ns(ktime_sub(current_packet_time, syn_history.timestamp));
		time_diff_sec = div_s64(time_diff_nano, NSEC_PER_SEC);
		if(time_diff_sec <= SCAN_TIMEOUT)
		{
			syn_history.counter++;
			if(syn_history.counter >= SYN_SCAN_THRESH)
			{
				printk(KERN_WARNING "-_-_-_-SYN Scan DETECTED-_-_-_-");
				prints(syn_history.src_addr);
				syn_history.counter = 0;
			}
		}
	}
	else
	{
		setparams(iphdr, current_packet_time, &syn_history);
		/*
		syn_history.timestamp = current_packet_time;
		syn_history.src_addr = s_addr;
		syn_history.counter = 0;
		*/
	}
	if(!(tcph->syn ||tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin) && null_history.src_addr == s_addr) //NULL scan
	{
		time_diff_nano = ktime_to_ns(ktime_sub(current_packet_time, null_history.timestamp));
		time_diff_sec = div_s64(time_diff_nano, NSEC_PER_SEC);
		if(time_diff_sec <= SCAN_TIMEOUT)
		{
			null_history.counter++;
			if(null_history.counter >= NULL_SCAN_THRESH)
			{
				printk(KERN_WARNING "-_-_-_-NULL Scan DETECTED-_-_-_-");
				prints(null_history.src_addr);
				null_history.counter = 0;
			}
		}
	}
	else
	{
		setparams(iphdr, current_packet_time, &null_history);
		/*
		null_history.timestamp = current_packet_time;
		null_history.src_addr = s_addr;
		null_history.counter = 0;
		*/
	}
	if(tcph->fin && tcph->urg && tcph->psh && !(tcph->ack || tcph->rst || tcph->syn) && xmas_history.src_addr == s_addr) //XMAS scan
	{
		time_diff_nano = ktime_to_ns(ktime_sub(current_packet_time, xmas_history.timestamp));
		time_diff_sec = div_s64(time_diff_nano, NSEC_PER_SEC);
		if(time_diff_sec <= SCAN_TIMEOUT)
		{
			xmas_history.counter++;
			if(xmas_history.counter >= XMAS_SCAN_THRESH)
			{
				printk(KERN_WARNING "-_-_-_-XMAS Scan DETECTED-_-_-_-");
				prints(xmas_history.src_addr);
				xmas_history.counter = 0;
			}
		}
	}
	else
	{
		setparams(iphdr, current_packet_time, &xmas_history);
		/*
		xmas_history.timestamp = current_packet_time;
		xmas_history.src_addr = s_addr;
		xmas_history.counter = 0;
		*/
	}
	if(tcph->fin && !(tcph->urg || tcph->psh || tcph->ack || tcph->rst || tcph->syn) && fin_history.src_addr == s_addr) //FIN scan
	{
		time_diff_nano = ktime_to_ns(ktime_sub(current_packet_time, fin_history.timestamp));
		time_diff_sec = div_s64(time_diff_nano, NSEC_PER_SEC);
		if(time_diff_sec <= SCAN_TIMEOUT)
		{
			fin_history.counter++;
			if(fin_history.counter >= FIN_SCAN_THRESH)
			{
				printk(KERN_WARNING "-_-_-_-FIN Scan DETECTED-_-_-_-");
				prints(fin_history.src_addr);
				fin_history.counter = 0;
			}
		}
	}
	else
	{
		setparams(iphdr, current_packet_time, &fin_history);
		/*
		fin_history.timestamp = current_packet_time;
		fin_history.src_addr = s_addr;
		fin_history.counter = 0;
		*/
	}
		return NF_ACCEPT;
}
static int __init custom_init(void)
{ 
	int err;
	nfho.hook = (nf_hookfn *) detection_logic;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	err = nf_register_net_hook(&init_net, &nfho);
	if(err < 0)
	{
		printk(KERN_WARNING "Hook registration error returned with value of:%d\n", err); 
		return -1;
	}
	printk(KERN_ALERT "Anti-Nmap LOADED\n");
	return 0;	
}
static void __exit custom_exit(void) 
{ 
	nf_unregister_net_hook(&init_net, &nfho);
	printk(KERN_ALERT "Anti-Nmap UN-LOADED\n");	
}
module_init(custom_init);
module_exit(custom_exit);

/* 
-_-_-_- Comments/Additional(and unnecessary) features -_-_-_-
destination detection:
	d_addr = ntohl(iph->daddr);
	*add another variable to p_history struct to hold destination address(dst_addr, in this example)
	if(syn_history.dst_addr = d_addr)
		//logic
*/