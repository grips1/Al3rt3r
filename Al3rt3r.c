//implement reset feature that resets the packet counters to detect future scans.
//We need to add a time gap for scans to avoid setting off a dozen false positives.
//If the time diff between the packets is less than 5 seconds?
//So if(current_time_of_current_packet - syn_history.timestamp <= 5 sec) counter++;		?
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h
#include <linux/time.h>

#define XMAS_SCAN_THRESH 5
#define NULL_SCAN_THRESH 10
#define FIN_SCAN_THRESH 10
#define SYN_SCAN_THRESH 50
#define SCAN_TIMEOUT 5

MODULE_LICENSE("GPL");
MODULE_AUTHOR("grips1");
MODULE_DESCRIPTION("Nmap-specific IPS");

static struct nf_hook_ops nfho;

typedef struct packet_history
{
	u32 src_addr;
	ktime_t timestamp; //getnstimeofday(&timestamp) 	
	//timestamp is only supposed to hold the time, not be used in the function.
	//ktime_t? ^ apparently an ordinary unsigned long int ought to do it.	
	//why not make both current_packet_time and p_history.timestamp struct timespecs and just use the sec members?
	u16 counter;
} p_history;
p_history syn_history,
		  fin_history,
		  xmas_history,
		  null_history;

static unsigned int scan_detect_hook_func(const struct nf_hook_ops *ops, //handler? 
								struct sk_buff *skb, //captured packet
								const struct net_device *in, //incoming interface
								const struct net_device *out, //outgoing interface
								int (*okfn)(struct sk_buff *)) //?? What the fuck is this
{
	struct iphdr* iph;
	struct tcphdr* tcph;
	u32 saddr, daddr;
	ktime_t current_packet_time;
	current_packet_time = ktime_get_real(); //seconds since unix epoch
	if(!skb) return NF_ACCEPT; //if packet's empty
	iph = ip_hdr(skb);
	if(iph->protocol != IPPROTO_TCP) return NF_ACCPET; //if not TCP
	tcph = tcp_hdr(skb);
	s_addr = ntohl(iph->saddr);
	d_addr = ntohl(iph->daddr);
	if(tcph->syn && !(tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin) && syn_history.src_addr == s_addr)//SYN only TCP packet
	{
		//instead of printing an alert to kernel logs, implement an acoustic/visual alarm
		if(syn_history.src_addr == s_addr && (current_packet_time.tv_sec - syn_history.timestamp) <= SCAN_TIMEOUT)
		//current time - last packet time from host
		{
			syn_history.counter++;
			if(syn_history.counter == SYN_SCAN_THRESH) //SYN_SCAN_THRESH amount of SYN packets from single host
			{
				printk(KERN_ALERT "!!!!!\nSYN Scan DETECTED from source address:%pI4h\n!!!!!", syn_history.src_addr);
				syn_history.counter = 0;
			}
		}
	}
	else //for new source host, new address, time and counter set.
	{
		syn_history.timestamp = current_packet_time;
		syn_history.src_addr = s_addr;
		syn_history.counter = 0;
	}


/*		if(!(tcph->syn || tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin))//NULL scan
		{

		}
*/
		return NF_ACCEPT;

static int __init custom_init(void)
{ 
	nfho.hook = (nf_hookfn *) scan_detect_hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	if(!(nf_register_hook(&nfho)))
	{
		printk(KERN_WARNING "Hook registration error\n"); 
		return -1;
	}
	printk(KERN_ALERT "Anti-Nmap LOADED\n");
	return 0;	
}
static void __exit custom_exit(void) 
{ 
	nf_unregister_hook(&nfho);
	printk(KERN_ALERT "Anti-Nmap UN-LOADED\n");	
}
module_init(custom_init);
module_exit(custom_exit);