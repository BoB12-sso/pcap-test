#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#define ETHER_ADDR_LEN 6

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct libnet_ipv4_hdr
{
    u_int8_t ip_v:4,
        ip_hl:4;      /* header length */
                   /* version */
// #if (LIBNET_BIG_ENDIAN)
//     u_int8_t ip_v:4,       /* version */
//            ip_hl:4;        /* header length */
// #endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
// #if (LIBNET_LIL_ENDIAN)
    uint8_t  th_x2:4,         /* (unused) */
             th_off:4;        /* data offset */
// #endif
#if (LIBNET_BIG_ENDIAN)
    uint8_t  th_off:4,        /* data offset */
             th_x2:4;         /* (unused) */
#endif
    uint8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};

void print_mac(u_int8_t *mac){
	for(int i=0;i<6;i++){
		if (i==5){
			printf("%02x", mac[i]);
			break;
		}
		printf("%02x:",mac[i]);
	}	
}

//ip의 엔디안 변경
void print_ip(struct in_addr addr) {
    printf("%s", inet_ntoa(addr));
}

//엔디안 변경
void print_port(u_int16_t port) {
    printf("%u", ntohs(port));
}

void print_packet(struct pcap_pkthdr* header, const u_char* packet) {
    //이더넷 헤더 -> 패킷을 이더넷 헤더로 캐스팅
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;

    //ether_type -> 이더넷 상위 프로토콜 정보, IP = 0x0800
    if (ntohs(eth_hdr->ether_type) == 0x0800) {
        //ip헤더 = (ip헤더로 캐스팅)패킷+이더넷 사이즈
        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

        // ip_p -> ip 상위 프로토콜 정보, TCP = 0x06, UDP = 0x17
        if (ip_hdr->ip_p == 0x06) {
            //tcp헤더 = (캐스팅)패킷+이더넷 사이즈+IP 사이즈
            struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));
          
            //MAC 주소 출력
            printf("MAC: ");
            print_mac(eth_hdr->ether_shost);
            printf(" -> ");
            print_mac(eth_hdr->ether_dhost);
            printf("\n");

            // IP 주소 출력
            printf("IP: ");
            print_ip(ip_hdr->ip_src);
            printf(" -> ");
            print_ip(ip_hdr->ip_dst);
            printf("\n");

            // TCP(Port) 주소 출력
            printf("TCP: ");
            print_port(tcp_hdr->th_sport);
            printf(" -> ");
            print_port(tcp_hdr->th_dport);
            printf("\n");

            //print payload
            //이더넷 사이즈+ip사이즈+tcp 오프셋*4 -> TCP+Option을 계산하기 위해 word단위로 된 것에 4를 곱함
            int header_size = sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr)+(tcp_hdr->th_off)*4;

            //헤더에 GET이 있으면 페이로드 출력
            if(packet[header_size]==0x47&&packet[header_size+1]==0x45&&packet[header_size+2]==0x54){//GET
                printf("payload: ");
                int payload_len = header_size+1; //공백 넘기기

                for(int i=payload_len+3;i<payload_len+3+10;i++){
                    printf("%02x ",packet[i]);
                }
                printf("\n");
            } 
       }
    }
}

void payload(const u_char* payload, int payload_len) {
    printf("Payload:\n");
    for (int i = 0; i < payload_len; i++) {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// printf("%u bytes captured\n", header->caplen);
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        print_packet(header, packet);
	    printf("---------\n");
	}

	pcap_close(pcap);
}
