#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

FILE *result;

struct ether_addr{
 unsigned char mac_add[6];
};

struct ether_header{

	struct ether_addr etherdst_mac;
	struct ether_addr ethersed_mac;
	unsigned short ether_type;

};

#pragma pack(push, 2)  // 구조체 크기 정렬하기 = 2바이트 단위로 메모리 낭비없이 저장하기 위함. 
struct arp_header {

    unsigned short Hardw_type;
    unsigned short Prtoc_type;
    unsigned char Hardwadd_len;
    unsigned char Prtocadd_len;
    unsigned short Op_code;      // 패킷의 유형(req인지 rep인지 정의/req=1/rep=2)
    struct ether_addr Arpsed_mac;
    struct in_addr Arpsed_ip;
    struct ether_addr Arptar_mac;
    struct in_addr Arptar_ip;

};  
#pragma pack(pop)


void print_ether_header(const unsigned char *pkt_data,struct pcap_pkthdr* header);
void print_arp_header(const unsigned char *pkt_data);
void print_dns_message(const char *message, int msg_length);

int main() {

  pcap_if_t *alldevs;   // 포인터 alldevs의 자료형은 pcap_if_t
  pcap_if_t *d;
  int inum,res,i=0;
  struct pcap_pkthdr *header;  //pcap_pkthdr 구조체 : 
  const unsigned char *pkt_data;  //패킷을 저장할 공간
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  char packet_filter[] = ""; // 사용자가 원하는 프로토콜 필터 정보를 넣을 수 있는 공간
  struct bpf_program fcode; // 특정 프로토콜만을 캡쳐하기 위한 정책정보 저장

  if(pcap_findalldevs(&alldevs, errbuf) == -1) {  // alldevs 에 디바이스 목록 저장,에러시 errbuf에 에러저장 

    printf("Error in pcap_findalldevs: %s\n", errbuf);
    exit(1);

  }

  for(d=alldevs; d; d=d->next) {  //네트워트 디바이스 정보를 출력

    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  if(i==0) {  //디바이스 못찾을 경우 에러 

    printf("\nNo interfaces found! Make sure LiPcap is installed.\n");
    //return -1;
  }

  printf("Enter the interface number (1-%d):",i);
  scanf("%d", &inum);

  if(inum < 1 || inum > i) {  //입력한 값이 올바른지 판단 && : 둘다 참이어야 참

    printf("\nAdapter number out of range.\n");
    pcap_freealldevs(alldevs);  
    return -1;
  }

  for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);    //사용자가 선택한 장치 목록을 선택


  if((adhandle= pcap_open_live(d->name, 65536,   1,  1000,  errbuf  )) == NULL) {   //실제 네트워크 디바이스 오픈
    printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
    pcap_freealldevs(alldevs);
    return -1;
  }

  if (pcap_compile(adhandle, &fcode, packet_filter, 1, NULL) <0 )  { //패킷 필터링 정책을 위해 pcap_compile()함수 호출 //사용자가 정의한 필터링 룰을 bpf_program 구조체에 저장하여 특정 프로토콜 패킷만 수집

    printf("\nUnable to compile the packet filter. Check the syntax.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  if (pcap_setfilter(adhandle, &fcode)<0)  {  //pcap_compile() 함수내용을 적용하기 위해  pcap_setfilter() 함수가 사용된다.
    printf("\nError setting the filter.\n");
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->description);    // 디바이스 정보 출력
  pcap_freealldevs(alldevs);   // 해제

  //file open
  result=fopen("result.txt","w");

    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        if (res == 0) continue;
		  fprintf(result,"\nall context: \n");
        print_ether_header(pkt_data,header);
        pkt_data += 14;
        print_arp_header(pkt_data);
		  printf("end\n");
		  fflush(result);
    }
    
  return 0;

}



///// 출력

void print_ether_header(const unsigned char *pkt_data,struct pcap_pkthdr* header) {  // 이더넷 정보를 출력함

    struct ether_header *eth; //이더넷 헤더 정보를 담을 수 있는 공간의 이더헤더의 구조체를 eth로 지정
    eth = (struct ether_header *)pkt_data;  // 구조체 eth에 패킷 정보를 저장
    unsigned short eth_type;
    eth_type= ntohs(eth->ether_type);  // 인자로 받은 값을 리틀 엔디안 형식으로 바꾸어줌
	 u_int32_t ppay_len=header->len;
       const u_char* pkt=pkt_data;
		 for(int i=0;i<ppay_len;i++)
       {	fprintf(result,"%02x ",*(pkt_data+i));
			 if((i+1)%8==0)
				 fprintf(result," ");
			 if((i+1)%16==0)
				 fprintf(result,"\n");
		 }
    if (eth_type == 0x0806) {// ARP 패킷인 부분만 잡기!
        fprintf(result,"\n====== ARP packet ======\n");
        fprintf(result,"\nSrc MAC : ");
        for (int i=0; i<=5; i++)
            fprintf(result,"%02x ",eth->ethersed_mac.mac_add[i]);
        fprintf(result,"\nDst MAC : ");
        for (int i=0; i<=5; i++)
            fprintf(result,"%02x ",eth->etherdst_mac.mac_add[i]);
        fprintf(result,"\n");
    }
	 if(eth_type == 0x800){
		fprintf(result,"\n============IPv4===========\n");
		fprintf(result,"\nSrc MAC : ");
		for(int i=0;i<=5;i++)
			fprintf(result,"%02x ",eth->ethersed_mac.mac_add[i]);
		fprintf(result,"\nDst MAC : ");
		for(int i=0;i<=5; i++)
			fprintf(result,"%02x ",eth->etherdst_mac.mac_add[i]);
		fprintf(result,"\n\n");
		struct ip *ip_hdr=(struct ip *)(pkt_data+sizeof(struct ether_header));
		u_int8_t ip_type=ip_hdr->ip_p;
		u_int8_t ip_offset=ip_hdr->ip_hl;
		u_int8_t ip_version=ip_hdr->ip_v;

		char src_ip[16],dst_ip[16];
		char header[4];
		char* tmp = inet_ntoa(ip_hdr->ip_src);
		strcpy(src_ip,tmp);
		tmp=inet_ntoa(ip_hdr->ip_dst);
		strcpy(dst_ip,tmp);
		//tmp=inet_ntoa(ip_hdr->ip_hl);
		///strcpy(header,tmp);
		
		fprintf(result,"Src IP : %s\n",src_ip);
		fprintf(result,"Dst IP : %s\n",dst_ip);
		fprintf(result,"header length : %d\n",ip_offset);
		fprintf(result,"version : %d\n",ip_version);
		fprintf(result,"type of service : %02x\n",ip_hdr->ip_tos);
		fprintf(result,"total length : %d\n",ntohs(ip_hdr->ip_len));
		fprintf(result,"identification : %d\n",ntohs(ip_hdr->ip_id));
		fprintf(result,"TTL : %d\n",(unsigned int)ip_hdr->ip_ttl);
		fprintf(result,"Protocol : %d\n",(unsigned int)ip_hdr->ip_p);
		fprintf(result,"Checksum : 0x%04x\n",ntohs(ip_hdr->ip_sum));
		fprintf(result,"offset : %d\n",ntohs(ip_hdr->ip_off));
		fprintf(result,"Flag : 0x%04x\n",ntohs(ip_hdr->ip_off));


		//u_int32_t payload_len= header->caplen-sizeof(struct ether_header)-ip_offset*4;
		//u_int32_t max=payload_len >=16 ? 16 : payload_len;
		//const u_char* pkt_payload=pkt_data+sizeof(struct ether_header)+ip_offset*4;
		//printf("Payload : ");

		//if(!payload_len){
		//	printf("No payload\n");
		//}else{
		//	for(int i=0;i<max;i++)
		//		printf("%02x ",*(pkt_payload+i));
		//	printf("\n");

		//}
		if(ip_hdr->ip_p==IPPROTO_TCP){
			fprintf(result,"\n This is TCP Packet===================\n");
			struct tcphdr *tcp_hdr=(struct tcphdr *)(pkt_data+20+14);

			fprintf(result,"Src Port : %d\n",ntohs(tcp_hdr->source));
			fprintf(result,"Dst Port : %d\n",ntohs(tcp_hdr->dest));
			fprintf(result,"Sequence Number : %u\n",ntohl(tcp_hdr->seq));
			fprintf(result,"Acknowledge Number : %u\n",ntohl(tcp_hdr->ack_seq));
			fprintf(result,"Urgent Flag : %d\n",(unsigned int)tcp_hdr->urg);
			fprintf(result,"Acknowledgement Flag : %d\n",(unsigned int)tcp_hdr->ack);
			fprintf(result,"Push Flag : %d\n",(unsigned int)tcp_hdr->psh);
			fprintf(result,"Reset Flag : %d\n",(unsigned int)tcp_hdr->rst);
			fprintf(result,"Synchronise Flag : %d\n",(unsigned int)tcp_hdr->syn);
			fprintf(result,"Finish Flag: %d\n",(unsigned int)tcp_hdr->fin);
			fprintf(result,"Window : %d\n",ntohs(tcp_hdr->window));
			fprintf(result,"Checksum : %d\n",ntohs(tcp_hdr->check));
			fprintf(result,"Urgent Pointer : %d\n",tcp_hdr->urg_ptr);
			if(ntohs(tcp_hdr->source)==80||ntohs(tcp_hdr->dest)==80){
				fprintf(result,"This is HTTP\n");


			}

		}

		else if(ip_hdr->ip_p==IPPROTO_UDP){
			fprintf(result,"\nThis is UDP Packet===================\n");

			struct udphdr *udp_hdr=(struct udphdr *)(pkt_data+14+20);
			if(ntohs(udp_hdr->source)==53||ntohs(udp_hdr->dest)==53)
				fprintf(result,"This is DNS\n");
			fprintf(result,"Src Port : %d\n",ntohs(udp_hdr->source));
			fprintf(result,"Dst Port : %d \n", ntohs(udp_hdr->dest));
			fprintf(result,"Length : %d\n",ntohs(udp_hdr->len));
			fprintf(result,"Checksum : 0x%04x\n\n",ntohs(udp_hdr->check));
			//print DNS
			if(ntohs(udp_hdr->source)==53||ntohs(udp_hdr->dest)==53){
			u_int32_t dns_len=ppay_len-(14+20+8);
			const u_char* dns_print=pkt_data+(14+20+8);
			print_dns_message(dns_print,dns_len);
			fprintf(result,"\n");

			
			}

		}


	 }
}

const unsigned char *print_name(const unsigned char *msg,
          const unsigned char *p, const unsigned char *end) {
  
      if (p + 2 > end) {
          fprintf(stderr, "End of message.\n"); }
  
      if ((*p & 0xC0) == 0xC0) {
          const int k = ((*p & 0x3F) << 8) + p[1];
          p += 2;
          fprintf(result," (pointer %d) ", k);
          print_name(msg, msg+k, end);
          return p;
  
      } else {
          const int len = *p++;
          if (p + len + 1 > end) {
              fprintf(stderr, "End of message.\n");}
  
          fprintf(result,"%.*s", len, p);
          p += len;
          if (*p) {
              fprintf(result,".");
              return print_name(msg, p, end);
          } else {
              return p+1;
          }
      }
  }


void print_dns_message(const char *message,int msg_length){

if (msg_length < 12) {
          fprintf(stderr, "Message is too short to be valid.\n");
          
      }
  
      const unsigned char *msg = (const unsigned char *)message;
  
      fprintf(result,"ID = %0X %0X\n", msg[0], msg[1]);
  
      const int qr = (msg[2] & 0x80) >> 7;
     fprintf(result,"QR = %d %s\n", qr, qr ? "response" : "query");
  
      const int opcode = (msg[2] & 0x78) >> 3;
      fprintf(result,"OPCODE = %d ", opcode);
      switch(opcode) {
          case 0: fprintf(result,"standard\n"); break;
          case 1: fprintf(result,"reverse\n"); break;
          case 2: fprintf(result,"status\n"); break;
          default: fprintf(result,"?\n"); break;
      }
  
      const int aa = (msg[2] & 0x04) >> 2;
      fprintf(result,"AA = %d %s\n", aa, aa ? "authoritative" : "");
  
      const int tc = (msg[2] & 0x02) >> 1;
      fprintf(result,"TC = %d %s\n", tc, tc ? "message truncated" : "");
 
     const int rd = (msg[2] & 0x01);
     fprintf(result,"RD = %d %s\n", rd, rd ? "recursion desired" : "");
 
     if (qr) {
         const int rcode = msg[3] & 0x0F;
         fprintf(result,"RCODE = %d ", rcode);
         switch(rcode) {
             case 0: fprintf(result,"success\n"); break;
             case 1: fprintf(result,"format error\n"); break;
             case 2: fprintf(result,"server failure\n"); break;
             case 3: fprintf(result,"name error\n"); break;
				 case 4: fprintf(result,"not implemented\n"); break;
             case 5: fprintf(result,"refused\n"); break;
             default: fprintf(result,"?\n"); break;
         }
         if (rcode != 0) return;
	  }
 
     const int qdcount = (msg[4] << 8) + msg[5];
     const int ancount = (msg[6] << 8) + msg[7];
     const int nscount = (msg[8] << 8) + msg[9];
     const int arcount = (msg[10] << 8) + msg[11];
 
     fprintf(result,"QDCOUNT = %d\n", qdcount);
     fprintf(result,"ANCOUNT = %d\n", ancount);
     fprintf(result,"NSCOUNT = %d\n", nscount);
     fprintf(result,"ARCOUNT = %d\n", arcount);
 
 
     const unsigned char *p = msg + 12;
        const unsigned char *end = msg + msg_length;
 
     if (qdcount) {
         int i;
         for (i = 0; i < qdcount; ++i) {
             if (p >= end) {
                 fprintf(stderr, "End of message.\n"); }
 
             fprintf(result,"Query %2d\n", i + 1);
             fprintf(result,"  name: ");

             p = print_name(msg, p, end); fprintf(result,"\n");
 
             if (p + 4 > end) {
                 fprintf(stderr, "End of message.\n"); }
 
             const int type = (p[0] << 8) + p[1];
             fprintf(result,"  type: %d\n", type);
             p += 2;
 
            const int qclass = (p[0] << 8) + p[1];
             fprintf(result," class: %d\n", qclass);
             p += 2;
         }
     }
	if (ancount || nscount || arcount) {
         int i;
         for (i = 0; i < ancount + nscount + arcount; ++i) {
             if (p >= end) {
                 fprintf(stderr, "End of message.\n"); }
 
             fprintf(result,"Answer %2d\n", i + 1);
             fprintf(result,"  name: ");
 
             p = print_name(msg, p, end); fprintf(result,"\n");
 
             if (p + 10 > end) {
                 fprintf(stderr, "End of message.\n"); }
 
             const int type = (p[0] << 8) + p[1];
             fprintf(result,"  type: %d\n", type);
             p += 2;
 
             const int qclass = (p[0] << 8) + p[1];
             fprintf(result," class: %d\n", qclass);
             p += 2;
 
             const unsigned int ttl = (p[0] << 24) + (p[1] << 16) +
                 (p[2] << 8) + p[3];
             fprintf(result,"   ttl: %u\n", ttl);
             p += 4;
 
             const int rdlen = (p[0] << 8) + p[1];
             fprintf(result," rdlen: %d\n", rdlen);
             p += 2;
 
             if (p + rdlen > end) {
                 fprintf(stderr, "End of message.\n"); }
 
             if (rdlen == 4 && type == 1) {
                 /* A Record */
                 fprintf(result,"Address ");
                 fprintf(result,"%d.%d.%d.%d\n", p[0], p[1], p[2], p[3]);
 
             } else if (rdlen == 16 && type == 28) {
                 /* AAAA Record */
                 result,fprintf(result,"Address ");
                 int j;
                for (j = 0; j < rdlen; j+=2) {
						fprintf(result,"%02x%02x", p[j], p[j+1]);
        				if (j + 2 < rdlen) fprintf(result,":");
                 }
                 fprintf(result,"\n");
 
             } else if (type == 15 && rdlen > 3) {
                 /* MX Record */
                 const int preference = (p[0] << 8) + p[1];
                 fprintf(result,"  pref: %d\n", preference);
                 fprintf(result,"MX: ");
                 print_name(msg, p+2, end); printf("\n");
 
             } else if (type == 16) {
                 /* TXT Record */
                 fprintf(result,"TXT: '%.*s'\n", rdlen-1, p+1);
 
             } else if (type == 5) {
                 /* CNAME Record */
                 fprintf(result,"CNAME: ");
                 print_name(msg, p, end); printf("\n");
             }
 
             p += rdlen;
         }
     }
 
     if (p != end) {
         fprintf(result,"There is some unread data left over.\n");
     }
      fprintf(result,"\n");


}

void print_arp_header(const unsigned char *pkt_data) {  // ARP 패킷 정보를 출력

    struct arp_header *arprqip;
    struct arp_header *arprpip;
    struct arp_header *arpmac;
    struct arp_header *arpop;
    arprqip = (struct arp_header *)pkt_data;  
    arprpip = (struct arp_header *)pkt_data;
    arpmac = (struct arp_header *)pkt_data;
    arpop = (struct arp_header *)pkt_data;
    unsigned short Arpopcode = ntohs(arpop -> Op_code); 
	 unsigned short Hardw=ntohs(arpop->Hardw_type);
	 unsigned short proto=ntohs(arpop->Prtoc_type);
	 // 인자로 받은 값을 리틀 엔디안 형식으로 바꾸어줌

    if (Arpopcode == 0x0001) {  // request = 1
        fprintf(result," ******* request ******* \n");
        fprintf(result," Sender IP : %s\n ", inet_ntoa(arprqip -> Arpsed_ip));  // 바이트 순서의 32비트 값을 주소값으로 변환하기 위함(in_addr 필요)
        fprintf(result,"Target IP : %s\n ", inet_ntoa(arprqip -> Arptar_ip));
		  fprintf(result,"Hardw_type: %d", Hardw);
		  if(Hardw==0x0001)
			  fprintf(result," Ethernet\n");
		  fprintf(result,"Prtoc_type: %d",proto);
		  if(proto==0x0800)
			  fprintf(result," IPv4\n");
		  fprintf(result,"Hard_length: %d\n",arpop->Hardwadd_len);
		  fprintf(result,"Proto_length: %d\n",arpop->Prtocadd_len);

        fprintf(result,"\n");
    }
    
    if (Arpopcode == 0x0002) {  // reply = 2
        fprintf(result," ********  reply  ******** \n");
        fprintf(result," Sender IP  : %s\n ", inet_ntoa(arprpip -> Arpsed_ip));
        fprintf(result,"Sender MAC : ");
        for (int i=0; i <=5; i ++) fprintf(result,"%02x ",arpmac -> Arpsed_mac.mac_add[i]);
        fprintf(result,"\n");
        fprintf(result," Target IP  : %s\n ", inet_ntoa(arprpip -> Arptar_ip));
        fprintf(result,"Target MAC : ");
        for (int i=0; i <=5; i ++) fprintf(result,"%02x ",arpmac -> Arptar_mac.mac_add[i]);
        fprintf(result,"\n");
		  fprintf(result,"Hardw_type: %d", Hardw);
		  if(Hardw==0x0001)
            fprintf(result," Ethernet\n");
         fprintf(result,"Prtoc_type: %d",proto);
         if(proto==0x0800)
            fprintf(result," IPv4\n");
         fprintf(result,"Hard_length: %d\n",arpop->Hardwadd_len);
			fprintf(result,"Proto_length: %d\n",arpop->Prtocadd_len);


    }

}
