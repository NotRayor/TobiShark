#include <stdio.h>
#include <pcap.h>

#define BUFSIZE 1024

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "Couldn't open device %s :%s\n",dev,errbuf);
		return(2);
	}

	printf("is Work");
}
