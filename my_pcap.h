#include <pcap.h>		//for capturing network
#include <netinet/in.h> //for ntohs

// structure
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
//#include <netinet/tcp.h> was not used, since I used my own structure tr0y_tcphdr

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
//#include <netinet/if_ether.h>
#include <bits/ioctls.h>
//#include <linux/if_ether.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


/* Ethernet addresses are 6 bytes */
#define ETHER__ADDR_LEN	6
#define SIZE_ETHERNET 14  /* 6 + 6 + 2 = 14 */

// For reference. I did not use in main code!!

#define IP_ADDR_LEN 4

typedef struct arp_hdr_ {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
}arp_hdr;


typedef u_int tcp_seq;
struct tr0y_tcphdr {
    u_int16_t th_sport;     // source port 
    u_int16_t th_dport;     // destination port
    tcp_seq th_seq;     // sequence number 
    tcp_seq th_ack;     // acknowledgement number
    uint8_t th_offx2;

#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_int8_t th_flags;
#define TH_FIN    0x01
#define TH_SYN    0x02
#define TH_RST    0x04
#define TH_PUSH   0x08
#define TH_ACK    0x10
#define TH_URG    0x20
    u_int16_t th_win;       /* window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */
};

// Define some constants.
#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>

void print_mac(uint8_t *mac);
char *allocate_strmem(int len);
uint8_t *allocate_ustrmem (int len);
void GET_MYMAC(uint8_t *mac, char *interface);
/*
void SET_ARP_HDR(arp_hdr *arp_header, uint8_t *sender_mac, uint8_t *target_mac, int flag);
void GET_IP_ADDR(char *ip, char *interface);
uint8_t *SET_ETHER_PKT(uint8_t *dst_mac, uint8_t *src_mac, arp_hdr arp_header);
uint8_t *SEND_PACKET(uint8_t *request, char *interface, struct pcap_pkthdr *header, int flag);
uint8_t *PARSE_SENDER_MAC(const u_char *pkt_data);
*/
/*
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];   // destination eth addr 
    unsigned char   h_source[ETH_ALEN]; // source ether addr    
    unsigned short  h_proto;            // packet type ID field 
};*/
