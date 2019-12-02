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
char filter[80];
char filter2[80];
char file_token[4][40];
char file_list[1000][100]; // 파일 명이 매핑되는 배열


struct sockaddr_in source, dest;
struct sigaction act;

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
		printf("숫자 추출 : %d \n", atoi(number));
	}
}

// 선택한 파일의 이름 문자열을 쪼갠다.
// 쪼갠 문자열을 바탕으로, 연관된 IP를 출력하도록 만들어야한다.
// 그런데 AND로 둘다 선택이 가능한가??
// flag 0 : source ip, flag 1 : destination ip
int associate_file(int ch, int flag){
	
	sort_filelist();

	if(0 <= ch && ch <= packet_num){
		tokenizer(file_list[ch]);
		strcpy(filter2 ,file_token[1]);	
		printf("filter2 확인 :%s \n", filter2);
	}
	else{
		printf("입력값 재확인  \n");
	}
}

// 정렬 함수, -1이면 앞에, 1이면 뒤로 배치하면서 출력할 것이다.
static inline int datesort(const struct dirent** file1, const struct dirent** file2){
	struct stat info1, info2;
	char path1[PATH_MAX], path2[PATH_MAX];
	int rval = 0;

	sprintf(path1,"./logdir/%s", (*file1)->d_name);
	sprintf(path2, "./logdir/%s", (*file2)->d_name);


	rval = stat(path1, &info1);
	// -1 오류 발생
	if(rval){
		printf("stat error\n");
		return 0;
	}

	rval = stat(path2, &info2);
	if(rval){
		printf("stat error\n");
		return 0;
	}

	printf("시간비교 %s  %ld , %s %ld \n",(*file1)->d_name, info1.st_mtime,(*file2)->d_name, info2.st_mtime );
	/* stat.mtime 마지막으로 수정된 시간*/
	/* stat.ctime 마지막으로 상태가 변화한 시간 */
	return info1.st_mtime < info2.st_mtime;
}

int file_select(const struct dirent *entry)
{
	if(strstr(entry->d_name, filter) && strstr(entry->d_name, filter2)){
		return 1;
	}
	else{
		return 0;
	}
}


int main(int argc, char *argv[])
{
	int input, end_flag = 0;
	socklen_t len;

	while(!end_flag){

		print_menu();
		printf("\ninput : ");
		scanf("%d", &input);
	
		switch(input){
			case 1:
				while(packet_handler()){
					//sleep(1);
				}
				break;
			case 2:
				packet_analyze("");
				break;
			case 3:
				printf("\nfilter input : ");
				scanf("%s", filter);
				//packet_list();
				break;
			case 4:
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
	sprintf(filename, "./logdir/%d_%s_%s_%s.txt", packet_num, inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr), protocol_name);
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
	return 1;
}


int packet_analyze(char *filter){
	struct dirent **namelist;
	int count;
	int idx;
	const char *path = "./logdir";

	printf("fuction : packet_analyze:320\n");

	if((count = scandir(path, &namelist, file_select, datesort)) == -1){
		fprintf(stderr, "%s direntory scan error\n", path);
	}

	printf("반환된 count : %d\n", count);

	for(idx = 0; idx < count; idx++){
		//파일의 이름 테스트
		printf("%s\n", namelist[idx]->d_name);
		strcpy(file_list[idx], namelist[idx]->d_name);
	}

	//file_list에 데이터 저장, 디버깅 완료

	for(idx = 0; idx < count; idx++){
		free(namelist[idx]);
	}

	free(namelist);

	int input = 0;
	printf("프레임 번호를 입력하세요 : ");
	scanf(" %d", &input);
	getchar();
	associate_file(input, 0);

	return 0;

}

int packet_list()
{
	printf("동작시작");

	DIR *dir_ptr = NULL;
	char path[] = {"./logdir"};
	char filename[1024];
	struct stat buf;
	struct dirent *file = NULL;


	/*목록 읽을 디렉터리 명을 DIR로 리턴 */
	if((dir_ptr = opendir(path)) == NULL){
		return unlink(path);
	}


	/*처음부터 파일, 디렉터리 명을 한개씩 읽는다. */
	while((file = readdir(dir_ptr))!=NULL){
		
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

		//S_ISREG 일반파일 S_ISLNK 심볼릭 링크
		else if(S_ISREG(buf.st_mode) || S_ISLNK(buf.st_mode)){
			printf("파일이름  %s \n", file->d_name);
			tokenizer(file->d_name);
		}
	}
	closedir(dir_ptr);
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
	printf("3.set Filter \n");	
	printf("4.exit \n");
}

void tokenizer(char str[1024]){
	char *ptr = strtok(str, "_");
	int i = 0;

	while(ptr != NULL){
		strcpy(file_token[i], ptr);
		i++;
		ptr = strtok(NULL, "_");
	}
}
