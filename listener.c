#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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
	pcap_if_t* IF_list;
	char error_buffer[PCAP_ERRBUF_SIZE];
	printf("Initiliasing...\n");
	if(pcap_init(PCAP_MMAP_32BIT, error_buffer) != 0)
	{
		printf("Error initialising! See below:\n%s", error_buffer);
		return -1;
	}
 
	printf("Creating Interface list...\n");
	pcap_findalldevs(&IF_list, error_buffer); //reminder to add handler
	
	printf("The following are usable pcap interfaces:\n\n");
	print_IF_list(IF_list);
	pcap_freealldevs(IF_list);
	printf("Creating handler...\n");
	pcap_t* handler = pcap_create("enp0s3", error_buffer);
	if(handler == NULL)
	{
		printf("An error has occured while creating the handler! See below:\n%s\n", error_buffer);
		return -1;
	}
	pcap_set_snaplen(handler, 65535);
	int temp;
	printf("Setting immediate mode to handler...\n");
	if((temp = pcap_set_immediate_mode(handler, 1)) == 0)
		printf("Immediate mode set successfully.\n");
	else
		printf("Error setting immediate mode...\n");
	
	if((temp = pcap_activate(handler)) < 0)
	{
		printf("Fatal error activating handler! Did you use the magic word?\n");
		printf("Error code:%d\n", temp);
		return -1;
	}
	else if(temp > 0) printf("Handler activated with errors.\n");
	else printf("Handler activated flawlessly.\n");
	

	return 0;
}