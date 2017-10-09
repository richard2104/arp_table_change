#include <pcap.h>		//for capturing network
#include <stdint.h>
#include <netinet/in.h> //for ntohs

// structure
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
//#include <netinet/tcp.h> was not used, since I used my own structure tr0y_tcphdr

/* Ethernet addresses are 6 bytes */
#define ETHER__ADDR_LEN	6
#define SIZE_ETHERNET 14  /* 6 + 6 + 2 = 14 */

// For reference. I did not use in main code!!

#define IP_ADDR_LEN 4

struct arphdr{
    u_int16_t ar_hrd; // format of hardware address
    u_int16_t ar_pro; // format of protocol address
    u_int8_t ar_hln;  // length of hardware address
    u_int8_t ar_pln;  // length of protocol address
    u_int16_t ar_op;  // OP_CODE
    u_int8_t ar_sha[6];
    u_int8_t ar_sip[4];
    u_int8_t ar_tha[6];
    u_int8_t ar_tip[4];
};

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

/*
struct ip {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;       // header length 
    unsigned int ip_v:4;        // version 
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;        // version 
    unsigned int ip_hl:4;       // header length 
#endif
    u_int8_t ip_tos;            // type of service 
    u_short ip_len;         // total length 
    u_short ip_id;          // identification 
    u_short ip_off;         // fragment offset field 
#define IP_RF 0x8000            // reserved fragment flag 
#define IP_DF 0x4000            // dont fragment flag 
#define IP_MF 0x2000            // more fragments flag 
#define IP_OFFMASK 0x1fff       // mask for fragmenting bits 
    u_int8_t ip_ttl;            // time to live 
    u_int8_t ip_p;          // protocol 
    u_short ip_sum;         // checksum 
    struct in_addr ip_src, ip_dst;  // source and dest address 
};
*/


/*
struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];   // destination eth addr 
    unsigned char   h_source[ETH_ALEN]; // source ether addr    
    unsigned short  h_proto;            // packet type ID field 
};*/
