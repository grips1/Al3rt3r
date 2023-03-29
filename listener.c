#include <pcap.h>
#include <stdio.h>

void print_IF_list(pcap_if_t* IF_list) //works
{
    int count = 1;
	while(IF_list != NULL)
    {
        printf("IF Number: %d\nName: %s\n", count, IF_list->name);
        count++;
        IF_list = IF_list->next;
    }
}

int main()
{
	unsigned char packet;
	struct pcap_pkthdr header;
	int temp;
	pcap_if_t* IF_list;
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t* handler;
	printf("Initiliasing...\n");
	if(pcap_init(PCAP_MMAP_32BIT, error_buffer) != 0)
	{
		printf("Error initialising! See below:\n%s", error_buffer);
		return -1;
	}
	//list IFs
	printf("Creating Interface list...\n");
	pcap_findalldevs(&IF_list, error_buffer);
	printf("The following are usable pcap interfaces:\n\n");
	print_IF_list(IF_list);
	pcap_freealldevs(IF_list);
	//handler creation
	printf("Creating handler...\n");
	handler = pcap_open_live("enp0s3", 65535, 0, 20, &error_buffer[0]);
	if((handler = pcap_open_live("enp0s3", 65535, 0, 20, &error_buffer)) == NULL)
	{
		printf("Error creating handler! Quitting.\n");
		printf("%s\n", error_buffer);
		pcap_close(handler);
		return -1;
	}
	printf("Data link layer header is: %d\n", pcap_datalink(handler));
	if((packet = pcap_next(handler, &header)) == NULL) 
	{
		printf("Failure capturing packet!");	
		printf("length = %d\n", header.len);
		pcap_close(handler);
		return -1;
	}			
	printf("Packet of length %d read successfully!\n", header.len);
	pcap_close(handler);

	return 0;
	
	// DLT_EN10MB
	//pcap_lookupnet
	//pcap_next
	/* add filter for port 22 when finished with crafting the sniffer, 
	currently unnecessary at this early stage since linux doesn't have background traffic
	*/ 












//Apply pcap_create instead of pcap_open_live for more lines? Seems like a shitty thing to do...
/* 	printf("Setting immediate mode to handler...\n");
	if((temp = pcap_set_immediate_mode(handler, 1)) == 0)
		printf("Immediate mode set successfully.\n");
	else
		printf("Error setting immediate mode...\n");
	if((temp = pcap_activate(handler)) < 0)
	{
		printf("Fatal error activating handler!\n");
		printf("Error code:%d\n", temp);
		return -1;
	}
	else if(temp > 0) printf("Handler activated with errors.\n");
	else printf("Handler activated flawlessly.\n");
*/	

}