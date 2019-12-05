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
#include <time.h>
#include <pthread.h>
//디렉토리 생성 라이브러리
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
//시스템 관련 헤더
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/ip_icmp.h>  //icmp_추가


#define BUFFER_SIZE 65536
#define PATH_MAX 512

#define ICMP 1
#define TCP 6
#define UDP 17
#define DNS 53
#define HTTP 80

 

int rawsocket;
int packet_num = 0;
int remaining_data = 0;
int max_file; // 현재 받은 파일의 수
FILE *log_file;
FILE *log_file_dir;
FILE *read_file = NULL;
char filter[80];
char filter2[80]; // source ip
char filter3[80]; // dest ip 
char file_token[4][40];
char file_list[1000][100]; // 파일 명이 매핑되는 배열


struct sockaddr_in source, dest;
struct sigaction act;
pthread_mutex_t mutex;

int packet_handler(void);
int packet_analyze(char *filter);
int packet_list();

// Crtl+c 누르면 동작하는 시그널 핸들러.
void close_handler(void){
	printf("\n=====Pcap End=====\n");

	fclose(log_file);
	close(rawsocket);
}

void log_eth(struct ethhdr *eth);
void log_ip(struct iphdr *ip);
void log_icmp(struct icmp *icmp);			//icmp_추가
void log_ih_idseq(struct ih_idseq *ih_idseq); //icmp_추가
void log_tcp(struct tcphdr *tcp);
void log_udp(struct udphdr *udp);
void log_data(unsigned char *data, int remaining_data);

// 문자열 관련 함수
void print_eth(struct ethhdr *eth);
void print_menu();
void tokenizer(char str[1024]);

// 디렉터리 / 파일 관련 함수
void make_logdir();
void delete_logdir();
void get_logdir();
int rmdirs(const char *path, int force);

void sort_filelist(){
	char number[10];

	for(int i = 0; i < packet_num; i++){
		tokenizer(file_list[i]);
		strcpy(number, file_token[0]);
		//printf("숫자 추출 : %d \n", atoi(number));
	}
//	printf("84: sortfile debug\n");
//	printf("packet_num : %d \n", packet_num);
}

int associate_file(int ch, int flag){

	// ch범위를 벗어나면 필터동작 X, 번호를 다시 확인
	if(0 <= ch && ch <= packet_num){
		tokenizer(file_list[ch]);
		strcpy(filter2 ,file_token[1]);
		}
	else{
		printf("입력값 재확인  \n");
	}
}

// 파일 선택 함수 
int file_select(const struct dirent *entry)
{
	if(strstr(entry->d_name, filter) && (strstr(entry->d_name, filter2)))
	{
		return 1;
	}
	else{
		return 0;
	}
}

// ch. ch패킷 선택
void file_read(int ch)
{
	read_file = NULL;
	char dir_path[120] = "./logdir/";
	char path[120]; 
	strcpy(path, file_list[ch]);
	strcat(dir_path, path);

	read_file = fopen(dir_path,"r");
	printf("합친 문자열 %s \n", dir_path);

	if(read_file != NULL)
	{
		char strTemp[512];
		char *pStr;

		while( !feof(read_file))
		{
			pStr = fgets(strTemp, sizeof(strTemp), read_file);
			printf("%s", strTemp);
		}
		fclose(read_file);
	}
	else
	{
		printf("read_file Error \n");
	}

}

void packetSelect(){
	int input = 0;
	printf("분석할  패킷의 프레임 번호 : ");
	scanf(" %d", &input);
	getchar();
	// 100: 선택된 파일의 ip필터 적용
	file_read(input);
}

int main(int argc, char *argv[])
{
	int input, end_flag = 0;
	socklen_t len;
	pthread_mutex_init(&mutex, NULL);
	

	while(!end_flag){

		print_menu();
		printf("\ninput : ");
		scanf("%d", &input);
	
		switch(input){
			case 1:
				packet_handler();
				break;
			case 2:
				// file 출력 및 선택
				packet_analyze("");
				break;
			case 3: // 패킷 선택
				packetSelect();
				break;
			case 4: // 프로토콜 설정 
				printf("\nfilter input : ");
				scanf("%s", filter);
				printf("filter set...\n");
				break;
			case 5: // 연관패킷 설정
				printf("연관 프레임 번호를 입력하세요 : ");
				scanf(" %d", &input);
				getchar();
				// 100: 선택된 파일의 ip필터 적용
				associate_file(input, 0);
				break;
			case 6: // 필터 초기화
				strcpy(filter,"");
				strcpy(filter2,"");
				printf("filter reset...\n");
				break;
			case 7: // 종료 
				delete_logdir();
				exit(1);
				break;
			default:
				printf("Check your input\n");
				break;
		}

	}

	return 0;
}

//디렉토리 생성 함수
void make_logdir()
{
	char path[] = {"./logdir"};
	mkdir(path, 0755);
}

//디렉터리 삭제 함수
void delete_logdir()
{
	char path[] = {"./logdir"};
	int result = rmdirs(path, 1);

	if(result == -1){
		printf("delete_logdir Error\n");
	}
}


int rmdirs(const char *path, int force)
{
	DIR * dir_ptr = NULL;
	struct dirent *file = NULL;
	struct stat buf;//파일의 상태 정보를 저장하는 buf 구조체
	char filename[1024];

	/*목록 읽을 디렉터리 명을 DIR로 리턴 */
	if((dir_ptr = opendir(path)) == NULL){
		return unlink(path);
	}

	/*처음부터 파일, 디렉터리 명을 한개씩 읽는다. */
	while((file = readdir(dir_ptr))!=NULL){
		//readdir 파일명 중, 현재 디렉터리 나타내는 . 도 포함되어 있다.
		// . or ..을 확인해서, 동일할 시 continue로 넘겨서 무한루프를 막는다.
		if(strcmp(file->d_name,".")==0 || strcmp(file->d_name,"..")==0){
			continue;
		}

		//filename ./path
		sprintf(filename, "%s/%s", path, file->d_name);

		//lstat 링크 파일 자체 정보를 받아온다. 
		//파일 속성을 얻어 buf에 저장,
		if(lstat(filename,&buf)==-1){
			continue;
		}

		//  S_ISDIR 디렉터리 판별
		if(S_ISDIR(buf.st_mode)){
			// 검색된 파일이 디렉터리면 재귀호출로 하위 디렉터리 검색
			if(rmdirs(filename, force) == -1 && !force){
				return -1;
			}
		}
			//S_ISREG 일반파일 S_ISLNK 심볼릭 링크
		else if(S_ISREG(buf.st_mode) || S_ISLNK(buf.st_mode)){
			if(unlink(filename)==-1&&!force){
				return -1;
			}
			printf("파일삭제 %s \n", file->d_name);
		}
	}

	closedir(dir_ptr);
	return rmdir(path);
}


//ls 함수 대용
void get_logdir()
{
	log_file_dir = fopen("logdir_list.txt", "w");
    	DIR *dir = opendir("logdir");
    	if(dir == NULL)
    	{
        	printf("failed open\n");
    	}
 
    	struct dirent *de=NULL;
 
    	while((de = readdir(dir))!=NULL)
    	{
			// 파일 이름 저장
        	fprintf(log_file_dir, "%s\n",de->d_name);
    	}
    	closedir(dir);
	fclose(log_file_dir);
} 

int packet_handler(){

	struct sockaddr saddr;
	int saddr_len = sizeof(saddr);
	unsigned short iphdrlen;
	int protocol = 0, source_port = 0, dest_port = 0;
	unsigned char *buffer = (unsigned char*) malloc(BUFFER_SIZE); // receive data
	unsigned char protocol_name[10];
	int packet_len = 0;


	act.sa_handler=close_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags=0;
	sigaction(SIGINT, &act, 0);

	rawsocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(rawsocket<0)
	{
		printf("pcap end \n");
		return -1;
	}

	while(1){
	struct sockaddr saddr;
	saddr_len = sizeof(saddr);
	iphdrlen = 0;
	protocol = 0, source_port = 0, dest_port = 0;
	buffer = (unsigned char*) malloc(BUFFER_SIZE); // receive data
	protocol_name[10] = "";
	packet_len = 0;

	memset(buffer, 0, BUFFER_SIZE);

	int buflen=recvfrom(rawsocket, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);

	if(buflen <0){
		printf("error in reading recvfrom \n");
		return 0;
	}

	// L2 link Layer
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	
	
	// L3 Network Layer
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = ip->ihl * 4; 

	protocol = (unsigned int)ip->protocol;

	unsigned char * data = (buffer + iphdrlen + sizeof(struct ethhdr));	
	remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr));

	if (protocol == ICMP) {																//icmp_추가
		struct icmp *icmp = (struct icmp*)(buffer + sizeof(struct ethhdr) + iphdrlen);  //icmp_추가
		strcpy(protocol_name, "ICMP");													//icmp_추가
		source_port = ntohs(ip->saddr);													//icmp_추가	
		dest_port = ntohs(ip->daddr);								//icmp_추가		
		data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct icmp));	
		remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct icmp));
	}else if(protocol == TCP){				// L4 TransPort Layer
		struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
		strcpy(protocol_name,"TCP");
		source_port = ntohs(tcp->source);
		dest_port = ntohs(tcp->dest);
		data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));	
		remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
	}else if(protocol == UDP){
		struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
		strcpy(protocol_name,"UDP");
		source_port = ntohs(udp->source);
		dest_port = ntohs(udp->dest);
		data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));	
		remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
	}else if(protocol == HTTP){
		//printf("=====HTTP=====\n");
		//printf("%s\n", remaining_data); //세그멘테이션 오류, 이거 수정하면 동작이 될까?	
	}
	else{
		sprintf(protocol_name, "%d", protocol);
	}

	if(DNS == source_port || DNS == dest_port)
		strcpy(protocol_name,"DNS");
	else if(HTTP == source_port || HTTP == dest_port)
		strcpy(protocol_name,"HTTP");

	//packet_handler 변경 점	
	make_logdir();
	char filename[500];
	char str_frame[10];
	
	if(packet_num < 10){
		sprintf(str_frame,"000%d",packet_num);
	}
	else if(10 <= packet_num && packet_num < 100){
		sprintf(str_frame,"00%d",packet_num);
	}else if(100 <= packet_num && packet_num < 1000){
		sprintf(str_frame, "0%d", packet_num);
	}else if(1000 <= packet_num && packet_num < 10000){
		sprintf(str_frame, "%d", packet_num);
	}

	char destIP[60];
	strcpy(destIP, inet_ntoa(dest.sin_addr));
	sprintf(filename, "./logdir/%s_%s_%s_%s.txt",str_frame, inet_ntoa(source.sin_addr), destIP, protocol_name);
	log_file = fopen(&filename, "w");
	log_eth(eth);
	log_ip(ip);
	if (protocol == ICMP) {																//icmp_추가
		struct icmp *icmp = (struct icmp*)(buffer + sizeof(struct ethhdr) + iphdrlen);  //icmp_추가
		log_icmp(icmp);																	//icmp_추가
	}else if(protocol == TCP){
		struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
		log_tcp(tcp);
	}
	else if(protocol == UDP){
		struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + iphdrlen);
		log_udp(udp);
	}
	else if(protocol == HTTP){
		
	}
	log_data(data, remaining_data);

	fclose(log_file);
	get_logdir();

	printf("Num %d\t", packet_num);
	printf("Source %s\t", inet_ntoa(source.sin_addr));
	printf("Dest %s\t", inet_ntoa(dest.sin_addr));
	printf("Protocol %s\t \n", protocol_name);

	packet_num++;
	max_file = packet_num;

	free(buffer);
	}

	return 1;
}


int packet_analyze(char *filter){
	struct dirent **namelist;
	int plus = 0;
	int count;
	int idx;
	const char *path = "./logdir";

	printf("fuction : packet_analyze:397\n");

	if((count = scandir(path, &namelist, file_select, alphasort)) == -1){
		fprintf(stderr, "%s direntory scan error\n", path);
	}

	// .이나 ..을 계산에서 제외시키기 위함이다.
	if(strcmp(filter,"")==0 && strcmp(filter2,"")==0){
		plus = 2;
	}

	printf("반환된 count : %d\n", count);

	for(idx = plus; idx < count; idx++){
		//파일의 이름 출력
		printf("%s\n", namelist[idx]->d_name);
		strcpy(file_list[idx - plus], namelist[idx]->d_name);
	}

	//file_list에 데이터 저장, 디버깅 완료

	for(idx = 0; idx < count; idx++){
		free(namelist[idx]);
	}

	free(namelist);

	return 0;

}

void log_eth(struct ethhdr *eth){

	fprintf(log_file,"\n===== Ethernet Header =====\n");
	fprintf(log_file,"Source Address %.2X %.2X %.2X %.2X %.2X %.2X \n", 
			eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3],
			eth->h_source[4], eth->h_source[5]);
	fprintf(log_file,"Destination Address :%.2X %.2X %.2X %.2X %.2X %.2X \n",
			eth->h_dest[0], eth->h_dest[1],eth->h_dest[2], eth->h_dest[3],
			eth->h_dest[4], eth->h_dest[5]);

}

void log_ip(struct iphdr *ip){

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

void log_icmp(struct icmp *icmp) {													//icmp_추가
	struct ih_idseq *ih_idseq;														//icmp_추가
	fprintf(log_file, "===== ICMP =====\n");										//icmp_추가	
	fprintf(log_file, "-Type : %d \n", (unsigned int)icmp->icmp_type);				//icmp_추가
	fprintf(log_file, "-Code : %d \n", (unsigned int)icmp->icmp_code);				//icmp_추가
	fprintf(log_file, "-Checksum : %x \n", (unsigned int)icmp->icmp_cksum);			//icmp_추가
	fprintf(log_file, "-Identifier : %d \n", (unsigned int)ih_idseq->icd_id);		//icmp_추가
	fprintf(log_file, "-Sequence number : %d \n", (unsigned int)ih_idseq->icd_seq);//icmp_추가
}																					//icmp_추가
					

void log_tcp(struct tcphdr *tcp){
	fprintf(log_file,"===== TCP =====\n");
	fprintf(log_file, " -Source Port : %d \n", ntohs(tcp->source));
	fprintf(log_file," -Destination Port : %d \n", ntohs(tcp->dest));
	fprintf(log_file," -Sequence Number : %x \n", tcp->seq);
	fprintf(log_file," -Acknowldge Number : %x \n", tcp->ack_seq);
}

void log_udp(struct udphdr *udp){
	fprintf(log_file,"===== UDP =====\n");
	fprintf(log_file, " -Source Port : %d \n", ntohs(udp->source));
	fprintf(log_file," -Destination Port : %d \n", ntohs(udp->dest));
	fprintf(log_file," -UDP Length : %d \n", ntohs(udp->len));
	fprintf(log_file," -Checksum  : %d \n", ntohs(udp->check));
}

void log_data(unsigned char *data, int remaining_data){

	fprintf(log_file,"===== DATA =====\n");
	for(int i = 0; i < remaining_data; i++){
	

		if(i!=0){
			fprintf(log_file, "%.2x ", data[i]);
		}
	
		if(i%16 == 0)
			fprintf(log_file, "\n");


	}

	fprintf(log_file, "\n");	
}

void print_eth(struct ethhdr *eth){
	printf("=====Ethernet Header===== \n");

	// Ethernet 6byte address
	printf("Source Address %.2X %.2X %.2X %.2X %.2X %.2X \n",
			eth->h_source[0], eth->h_source[1], eth->h_source[2], 
			eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("Destination Address :%.2X %.2X %.2X %.2X %.2X %.2X \n", 
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
			eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("Protocol :%x \n", eth->h_proto); // next layer information

}

void print_menu(){
	printf("\n=====Program Menu=====\n");
	printf("1.Capture Start \n");
	printf("2.List View \n");
	printf("3.Select Packet\n");
	printf("4.set Filter \n");
	printf("5.set associate Filter \n");
	printf("6.reset Filter \n");
	printf("7.exit \n");
}

void tokenizer(char str[1024]){
	char temp[1024];
	char *ptr;
	int i = 0;

	strcpy(temp, str);
	ptr = strtok(temp, "_");
	
	while(ptr != NULL){
		strcpy(file_token[i], ptr);
		printf("%s ",file_token[i]);
		i++;
		ptr = strtok(NULL, "_");
	}
}
