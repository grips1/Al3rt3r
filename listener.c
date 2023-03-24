/* Notes for future exploration:
* Make the listener a header file, then perform the socket creation, listening, 
etc. through the header file. Makes this project easier to maintain lol 


*/



#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h> /* Included only for portability reasons. If this program were running on Linux strictly, it wouldn't be necessary.  */
#include <arpa/inet.h>



int main()
{
	//create socket file descriptor + address options
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);/* not AF_UNIX, "local" means on the same machine */
	if(!sockfd)
	{
		perror("Sockfd");
		return -1;
	}
	int PORT = 6969;
	struct sockaddr_in mysock = {0};
	mysock.sin_family = AF_INET;
	mysock.sin_port = htons(22);
	inet_aton("192.168.14.82", (struct in_addr *)& mysock.sin_addr.s_addr);
	socklen_t mysock_size = sizeof(mysock);
	if((bind(sockfd, (struct sockaddr*)& mysock, mysock_size) < 0))
	{
		perror("Socket Binding");
		return -1;
	}
	if((listen(sockfd, 1)) < 0) 
	{
		perror("Fatal Listening Error");
		return -1;
	}
	accept(sockfd, (struct sockaddr*) &mysock, &mysock_size);
	return 0;





}