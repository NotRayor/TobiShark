#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <memory.h>
#include <fcntl.h>
#include <signal.h>

#define BUFFER_SIZE 65536

#define ICMP 1
#define TCP 6
#define UDP 17



int rawsocket;
int packet_num = 0;
FILE *log_file;


void packet_handler(void);
void log_eth(struct ethhdr *eth);
void log_ip(struct iphdr *ip);
void log_tcp(struct tcphdr *tcp);
void log_udp(struct udphdr *udp);
void log_data(unsigned char *data, int remaining_data);

void print_eth(struct ethhdr *eth);


int main(int argc, char *argv[])
{
	log_file = fopen("log_file.txt", "w");
	int input;
	socklen_t len;

	struct sigaction act;


	rawsocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(rawsocket<0)
	{
		printf("error in socket \n");
		return -1;
	}

//	signal(SIGALRM, packet_handler);
//	alarm(2);
	act.sa_handler=packet_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags=0;
	sigaction(SIGALRM, &act, 0);

	alarm(2);

	// end
	fclose(log_file);
	close(rawsocket);
}


// timeout
void packet_handler(){

	struct sockaddr saddr;
	int saddr_len = sizeof(saddr);
	unsigned short iphdrlen;
	int protocol = 0;
	unsigned char *buffer = (unsigned char*) malloc(65536); // receive data

	memset(buffer, 0, BUFFER_SIZE);

	int buflen=recvfrom(rawsocket, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
	if(buflen <0){
		printf("error in reading recvfrom \n");
		exit(1);
	}

	// L2 link Layer
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	eth_log(eth);
	
	// L3 Network Layer
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = ip->ihl * 4; 
	ip_log(ip);

	protocol = (unsigned int)ip->protocol;
	

	// L4 Transport Layer
	if(protocol == TCP){
		printf("protocol : TCP \n");
		struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
		tcp_log(tcp);

	}else if(protocol == UDP){
		printf("protocol : UDP \n");
		struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
		udp_log(udp);

	}else{
		printf("protocol : %d \n", protocol);
	}
	
	printf("Num %d|Time %d|Source %s|Destination %s|Protocol %d|Length %d ",
			packet_num, 0, "source ip","dest ip", protocol, sizeof(buffer));
			
}

void log_eth(struct ethhdr *eth){

	fprintf(log_file,"\n===== Ethernet Header =====\n");
	fprintf(log_file,"Source Address %.2X %.2X %.2X %.2X %.2X %.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	fprintf(log_file,"Destination Address :%.2X %.2X %.2X %.2X %.2X %.2X \n", eth->h_dest[0], eth->h_dest[1],eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);


}

void log_ip(struct iphdr *ip){
	struct sockaddr_in source, dest;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;

	fprintf(log_file,"\n===== IP Header =====\n");
	fprintf(log_file," -Version :%d \n", (unsigned int)ip->version);
	fprintf(log_file," -Internet Header Length(IHL) : %d bits \n", (unsigned int)ip->ihl * 4);
	fprintf(log_file," -Type Of Service :%d \n", (unsigned int)ip->tos);
	fprintf(log_file," -Total Length :%d Bytes \n", ntohs(ip->tot_len));
	fprintf(log_file," -Identification :%d \n", ntohs(ip->id));
	fprintf(log_file," -Time To Live :%d \n", (unsigned int)ip->ttl);
	fprintf(log_file," -Protocol :%d \n", (unsigned int)ip->protocol);
	fprintf(log_file," -Header Checksum :%d \n", htons(ip->check));
	fprintf(log_file," -Source IP :%s \n", inet_ntoa(source.sin_addr));
	fprintf(log_file," -Destination IP :%s \n", inet_ntoa(dest.sin_addr));
}

void log_tcp(struct tcphdr *tcp){
		fprintf(log_file,"===== TCP =====\n");
		fprintf(log_file, " -Source Port : %d \n", ntohs(tcp->source));
		fprintf(log_file," -Destination Port : %d \n", ntohs(tcp->dest));
		fprintf(log_file," -Sequence Number : %x \n", tcp->seq);
		fprintf(log_file," -Acknowldge Number : %x \n", tcp->ack_seq);}

void log_udp(struct udphdr *udp){
		fprintf(log_file,"===== UDP =====\n");
		fprintf(log_file, " -Source Port : %d \n", ntohs(udp->source));
		fprintf(log_file," -Destination Port : %d \n", ntohs(udp->dest));
		fprintf(log_file," -UDP Length : %d \n", ntohs(udp->len));
		fprintf(log_file," -Checksum  : %d \n", ntohs(udp->check));
}

void log_data(unsigned char *data, int remaining_data){	
	for(int i = 0; i < remaining_data; i++){
		if(i!=0 && i%16 == 0){
			fprintf(log_file,"\n");
			fprintf(log_file, "%.2x ", data[i]);
		}
	}
	fprintf(log_file, "\n");	
}

void print_eth(struct ethhdr *eth){
	printf("=====Ethernet Header===== \n");

	// Ethernet 6byte address
	printf("Source Address %.2X %.2X %.2X %.2X %.2X %.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("Destination Address :%.2X %.2X %.2X %.2X %.2X %.2X \n", eth->h_dest[0], eth->h_dest[1],eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("Protocol :%x \n", eth->h_proto); // next layer information

}




