#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include "my_pcap.h"

void callback(u_char *p, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char* argv[]) {
   
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE]; // 256
    pcap_t *pcd;
    
    u_char* broadcast = '';
    int length = 0;
    unsigned char packet[1500];

    if (argc != 4){
        puts("[-]Usage : ./arp_send [interface] [sender_ip] [target_ip]");
        return -1;
    }
	// pcap_lookupdev for setting the device
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(1);
	}
    //pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
    pcd = pcap_open_live(dev, BUFSIZ,  0/*NON-PROMISCUOUS*/, -1, errbuf);

    if (pcd == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        exit(1);


	// 1st stage: making ARP packet (request) or you can just broadcast.
	memset(packet, 0, sizeof(packet));


	// 2nd stage: sending ARP packet for getting victim's mac address
    if(pcap_sendpacket(pcd,packet,length) != 0 ) {
       fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(pcd));
       return -1;
    }
	

	// 3rd stage: capturing the ARP packet (reply) for getting victim's mac address
	pcap_loop(pcd, 0, callback, NULL);


}

void callback(u_char *p, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    struct ether_header *etherHdr; // <netinet/ether.h>
    struct ip *ipHdr; // <netinet/ip.h>
    struct tr0y_tcphdr *tcpHdr; // not in <netinet/tcp.h> , my own tcp_header
    u_int hlen; //tcp header length
    char *data_area;




}



