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
#include <linux/netfilter_ipv4.h>
#include <linux/time.h>
#include <linux/timekeeping.h>

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
	u16 counter;
} p_history;
	//timestamp is only supposed to hold the time, not be used in the function.
	//ktime_t? ^ apparently an ordinary unsigned long int ought to do it.	
	//why not make both current_packet_time and p_history.timestamp struct timespecs and just use the sec members?

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


static unsigned int scan_detect_hook_func(void* priv,
										  struct sk_buff* sk_buff,
										  const struct nf_hook_state* state)

								/*const struct nf_hook_ops *ops, //handler? 
								struct sk_buff *sk_buff, //captured packet
								const struct net_device *in, //incoming interface
								const struct net_device *out, //outgoing interface
								int (*okfn)(struct sk_buff *)) //?? What the fuck is this*/
{
	struct iphdr* iph;
	struct tcphdr* tcph;
	u32 s_addr;

	//struct timespec current_packet_time, time_diff;
	//long time_diff_sec;
	//current_packet_time = ktime_to_timespec(ktime_get_real()); //gets time

	ktime_t current_packet_time;
	s64 time_diff_nano, time_diff_sec;
	current_packet_time = ktime_get_real();

	if(!sk_buff) return NF_ACCEPT; //if packet's empty
	iph = ip_hdr(sk_buff);
	if(iph->protocol != IPPROTO_TCP) return NF_ACCEPT; //if not TCP
	tcph = tcp_hdr(sk_buff);
	s_addr = ntohl(iph->saddr);
	//d_addr = ntohl(iph->daddr);
	if(tcph->syn && !(tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin) && syn_history.src_addr == s_addr)//SYN only TCP packet
	{
		//instead of printing an alert to kernel logs, implement an acoustic/visual alarm
		//same address, same TCP flag
		
		//time_diff = timespec_sub(current_packet_time, syn_history.timestamp);
		//time_diff_sec = time_diff.tv_sec;
		time_diff_nano = ktime_to_ns(ktime_sub(current_packet_time, syn_history.timestamp));
		time_diff_sec = div_s64(time_diff_nano, NSEC_PER_SEC);
		if(time_diff_sec <= SCAN_TIMEOUT)
		//current time - last packet time from host
		{
			syn_history.counter++;
			if(syn_history.counter >= SYN_SCAN_THRESH) //SYN_SCAN_THRESH amount of SYN packets from single host
			{
				printk(KERN_ALERT "!!!!!\nSYN Scan DETECTED\n!!!!!");
				prints(syn_history.src_addr);
				syn_history.counter = 0;
			}
		}
	}
	else //for new source host, new address, time and counter set.
	{
		syn_history.timestamp = current_packet_time; //sets the time
		syn_history.src_addr = s_addr;
		syn_history.counter = 0;
	}


/*		if(!(tcph->syn || tcph->urg || tcph->ack || tcph->psh || tcph->rst || tcph->fin))//NULL scan
		{

		}
*/
		return NF_ACCEPT;
}
static int __init custom_init(void)
{ 
	int err;
	nfho.hook = (nf_hookfn *) scan_detect_hook_func;
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

/*Important comment from GPT for tomorrow:
Q:So when NF_INET_PRE_ROUTING is the hook point defined,
the module intercepts all packets that their destination is the same as the local network interface?

A:No, when the NF_INET_PRE_ROUTING hook point is defined, the module intercepts all packets that are entering the network stack, regardless of their destination. 
The hook function is invoked for each incoming packet before any routing decisions are made.

At the NF_INET_PRE_ROUTING hook point, the module has the opportunity to inspect and modify the intercepted packets before the kernel performs any further processing, such as routing or forwarding. 
This allows the module to analyze packet headers, perform security checks, or implement other custom behavior.

The hook function is called for all packets arriving on any network interface, regardless of their destination.
 It is important to note that the hook function is called in the context of the networking stack, before any routing decisions have been made based on the packet's destination address. 
 Therefore, it provides an early interception point for packet processing in the kernel.
*/